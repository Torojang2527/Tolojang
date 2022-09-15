package view

import (
	"fmt"

	"github.com/cli/cli/v2/api"
	"github.com/cli/cli/v2/internal/ghrepo"
	runShared "github.com/cli/cli/v2/pkg/cmd/run/shared"
	"github.com/cli/cli/v2/pkg/cmd/workflow/shared"
	workflowShared "github.com/cli/cli/v2/pkg/cmd/workflow/shared"
)

type workflowRuns struct {
	Total int
	Runs  []runShared.Run
}

func getWorkflowRuns(client *api.Client, repo ghrepo.Interface, workflow *shared.Workflow) (workflowRuns, error) {
	var wr workflowRuns
	var result runShared.RunsPayload
	path := fmt.Sprintf("repos/%s/actions/workflows/%d/runs?per_page=%d&page=%d", ghrepo.FullName(repo), workflow.ID, 5, 1)

	err := client.REST(repo.RepoHost(), "GET", path, nil, &result)
	if err != nil {
		return wr, err
	}

	wr.Total = result.TotalCount
	wr.Runs = append(wr.Runs, result.WorkflowRuns...)

	// Set WorkflowRun.name by getting the name from the workflow
	workflows, err := workflowShared.GetWorkflows(client, repo, 0)
	if err != nil {
		return wr, err
	}

	wfIDToName := map[int64]string{}
	for _, wf := range workflows {
		wfIDToName[wf.ID] = wf.Name
	}
	for i, run := range wr.Runs {
		if name, ok := wfIDToName[run.WorkflowID]; !ok {
			return wr, fmt.Errorf("could not find workflow for workflow ID %d", run.WorkflowID)
		} else {
			wr.Runs[i].Name = name
		}
	}

	return wr, nil
}
