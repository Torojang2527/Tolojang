package api

import (
	"fmt"
	"time"
)

type PullRequestsPayload struct {
	ViewerCreated   []PullRequest
	ReviewRequested []PullRequest
	CurrentPR       *PullRequest
}

type PullRequest struct {
	Number      int
	Title       string
	URL         string
	HeadRefName string
}

type Repo interface {
	RepoName() string
	RepoOwner() string
}

type IssuesPayload struct {
	Assigned  []Issue
	Mentioned []Issue
	Recent    []Issue
}

type Issue struct {
	Number int
	Title  string
}

func Issues(client *Client, ghRepo Repo, currentUsername string) (*IssuesPayload, error) {
	type issues struct {
		Issues struct {
			Edges []struct {
				Node Issue
			}
		}
	}

	type response struct {
		Assigned  issues
		Mentioned issues
		Recent    issues
	}

	query := `
    fragment issue on Issue {
      number
      title
    }
    query($owner: String!, $repo: String!, $since: DateTime!, $viewer: String!, $per_page: Int = 10) {
      assigned: repository(owner: $owner, name: $repo) {
        issues(filterBy: {assignee: $viewer}, first: $per_page) {
          edges {
            node {
              ...issue
            }
          }
        }
      }
      mentioned: repository(owner: $owner, name: $repo) {
        issues(filterBy: {mentioned: $viewer}, first: $per_page) {
          edges {
            node {
              ...issue
            }
          }
        }
      }
      recent: repository(owner: $owner, name: $repo) {
        issues(filterBy: {since: $since, orderBy: {field: CREATED_AT, direction: DESC}}, first: $per_page) {
          edges {
            node {
              ...issue
            }
          }
        }
      }
    }
  `

	owner := ghRepo.RepoOwner()
	repo := ghRepo.RepoName()
	since := time.Now().UTC().Add(time.Hour * -24).Format("2006-01-02T15:04:05-0700")
	variables := map[string]interface{}{
		"owner":  owner,
		"repo":   repo,
		"viewer": currentUsername,
		"since":  since,
	}

	var resp response
	err := client.GraphQL(query, variables, &resp)
	if err != nil {
		return nil, err
	}

	var assigned []Issue
	for _, edge := range resp.Assigned.Issues.Edges {
		assigned = append(assigned, edge.Node)
	}

	var mentioned []Issue
	for _, edge := range resp.Mentioned.Issues.Edges {
		mentioned = append(mentioned, edge.Node)
	}

	var recent []Issue
	for _, edge := range resp.Recent.Issues.Edges {
		recent = append(recent, edge.Node)
	}

	payload := IssuesPayload{
		assigned,
		mentioned,
		recent,
	}

	return &payload, nil
}

func PullRequests(client *Client, ghRepo Repo, currentBranch, currentUsername string) (*PullRequestsPayload, error) {
	type edges struct {
		Edges []struct {
			Node PullRequest
		}
		PageInfo struct {
			HasNextPage bool
			EndCursor   string
		}
	}

	type response struct {
		Repository struct {
			PullRequests edges
		}
		ViewerCreated   edges
		ReviewRequested edges
	}

	query := `
    fragment pr on PullRequest {
      number
      title
      url
      headRefName
    }

    query($owner: String!, $repo: String!, $headRefName: String!, $viewerQuery: String!, $reviewerQuery: String!, $per_page: Int = 10) {
      repository(owner: $owner, name: $repo) {
        pullRequests(headRefName: $headRefName, states: OPEN, first: 1) {
          edges {
            node {
              ...pr
            }
          }
        }
      }
      viewerCreated: search(query: $viewerQuery, type: ISSUE, first: $per_page) {
        edges {
          node {
            ...pr
          }
        }
        pageInfo {
          hasNextPage
        }
      }
      reviewRequested: search(query: $reviewerQuery, type: ISSUE, first: $per_page) {
        edges {
          node {
            ...pr
          }
        }
        pageInfo {
          hasNextPage
        }
      }
    }
  `

	owner := ghRepo.RepoOwner()
	repo := ghRepo.RepoName()

	viewerQuery := fmt.Sprintf("repo:%s/%s state:open is:pr author:%s", owner, repo, currentUsername)
	reviewerQuery := fmt.Sprintf("repo:%s/%s state:open review-requested:%s", owner, repo, currentUsername)

	variables := map[string]interface{}{
		"viewerQuery":   viewerQuery,
		"reviewerQuery": reviewerQuery,
		"owner":         owner,
		"repo":          repo,
		"headRefName":   currentBranch,
	}

	var resp response
	err := client.GraphQL(query, variables, &resp)
	if err != nil {
		return nil, err
	}

	var viewerCreated []PullRequest
	for _, edge := range resp.ViewerCreated.Edges {
		viewerCreated = append(viewerCreated, edge.Node)
	}

	var reviewRequested []PullRequest
	for _, edge := range resp.ReviewRequested.Edges {
		reviewRequested = append(reviewRequested, edge.Node)
	}

	var currentPR *PullRequest
	for _, edge := range resp.Repository.PullRequests.Edges {
		currentPR = &edge.Node
	}

	payload := PullRequestsPayload{
		viewerCreated,
		reviewRequested,
		currentPR,
	}

	return &payload, nil
}

func PullRequestsForBranch(client *Client, ghRepo Repo, branch string) ([]PullRequest, error) {
	type response struct {
		Repository struct {
			PullRequests struct {
				Edges []struct {
					Node PullRequest
				}
			}
		}
	}

	query := `
    query($owner: String!, $repo: String!, $headRefName: String!) {
      repository(owner: $owner, name: $repo) {
        pullRequests(headRefName: $headRefName, states: OPEN, first: 1) {
          edges {
            node {
				number
				title
				url
            }
          }
        }
      }
    }`

	variables := map[string]interface{}{
		"owner":       ghRepo.RepoOwner(),
		"repo":        ghRepo.RepoName(),
		"headRefName": branch,
	}

	var resp response
	err := client.GraphQL(query, variables, &resp)
	if err != nil {
		return nil, err
	}

	prs := []PullRequest{}
	for _, edge := range resp.Repository.PullRequests.Edges {
		prs = append(prs, edge.Node)
	}

	return prs, nil
}

func PullRequestList(client *Client, vars map[string]interface{}, limit int) ([]PullRequest, error) {
	type response struct {
		Repository struct {
			PullRequests struct {
				Edges []struct {
					Node PullRequest
				}
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			}
		}
	}

	query := `
    query(
		$owner: String!,
		$repo: String!,
		$limit: Int!,
		$endCursor: String,
		$baseBranch: String,
		$labels: [String!],
		$state: [PullRequestState!] = OPEN
	) {
      repository(owner: $owner, name: $repo) {
        pullRequests(
			states: $state,
			baseRefName: $baseBranch,
			labels: $labels,
			first: $limit,
			after: $endCursor,
			orderBy: {field: CREATED_AT, direction: DESC}
		) {
          edges {
            node {
				number
				title
				url
				headRefName
            }
		  }
		  pageInfo {
			  hasNextPage
			  endCursor
		  }
        }
      }
    }`

	prs := []PullRequest{}
	pageLimit := min(limit, 100)
	variables := map[string]interface{}{}
	for name, val := range vars {
		variables[name] = val
	}

	for {
		variables["limit"] = pageLimit
		var data response
		err := client.GraphQL(query, variables, &data)
		if err != nil {
			return nil, err
		}
		prData := data.Repository.PullRequests

		for _, edge := range prData.Edges {
			prs = append(prs, edge.Node)
			if len(prs) == limit {
				goto done
			}
		}

		if prData.PageInfo.HasNextPage {
			variables["endCursor"] = prData.PageInfo.EndCursor
			pageLimit = min(pageLimit, limit-len(prs))
			continue
		}
	done:
		break
	}

	return prs, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
