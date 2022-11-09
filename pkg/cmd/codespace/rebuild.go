package codespace

import (
	"context"
	"fmt"

	"github.com/cli/cli/v2/internal/codespaces/api"
	"github.com/cli/cli/v2/internal/codespaces/grpc"
	"github.com/spf13/cobra"
)

func newRebuildCmd(app *App) *cobra.Command {
	var codespace string
	var fullRebuild bool

	rebuildCmd := &cobra.Command{
		Use:   "rebuild",
		Short: "Rebuild a codespace",
		Long: `Rebuilding recreates your codespace. Your code and any current changes will be
preserved. Your codespace will be rebuilt using your working directory's
dev container. A full rebuild also removes cached Docker images.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Rebuild(cmd.Context(), codespace, fullRebuild)
		},
	}

	rebuildCmd.Flags().StringVarP(&codespace, "codespace", "c", "", "name of the codespace")
	rebuildCmd.Flags().BoolVar(&fullRebuild, "full", false, "perform a full rebuild")

	return rebuildCmd
}

func (a *App) Rebuild(ctx context.Context, codespaceName string, full bool) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	codespace, err := getOrChooseCodespace(ctx, a.apiClient, codespaceName)
	if err != nil {
		return err
	}

	// There's no need to rebuild again because users can't modify their codespace while it rebuilds
	if codespace.State == api.CodespaceStateRebuilding {
		fmt.Fprintf(a.io.Out, "%s is already rebuilding\n", codespace.Name)
		return nil
	}

	session, err := startLiveShareSession(ctx, codespace, a, false, "")
	if err != nil {
		return fmt.Errorf("starting Live Share session: %w", err)
	}
	defer safeClose(session, &err)

	a.StartProgressIndicatorWithLabel("Requesting rebuild")
	client, err := connectToGRPCServer(ctx, session, codespace.Connection.SessionToken)
	if err != nil {
		return fmt.Errorf("failed to connect to internal server: %w", err)
	}
	defer safeClose(client, &err)

	err = rebuildContainer(ctx, client, full)
	if err != nil {
		return fmt.Errorf("failed to rebuild container: %w", err)
	}
	a.StopProgressIndicator()

	fmt.Fprintf(a.io.Out, "%s is rebuilding\n", codespace.Name)
	return nil
}

func rebuildContainer(ctx context.Context, client *grpc.Client, full bool) error {
	ctx, cancel := context.WithTimeout(ctx, grpc.RequestTimeout)
	defer cancel()

	incremental := !full
	err := client.RebuildContainer(ctx, incremental)

	return err
}
