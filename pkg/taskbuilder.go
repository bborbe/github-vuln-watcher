// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"fmt"
	"strings"

	agentlib "github.com/bborbe/agent"
	"github.com/bborbe/agent/command/task"
)

// TaskConfig groups per-task envelope settings.
type TaskConfig struct {
	Stage string // "dev" or "prod" — emitted as the `stage` field
}

// ComputeTaskTitle returns the frozen title form:
// "Update Go <owner>-<repo> <sha[:7]>".
//
// Dash, not slash: CreateCommand.Validate rejects any '/' in a title, and
// SendCommand validates before publishing — a slash form would make every
// publish fail.
func ComputeTaskTitle(c Candidate) string {
	return fmt.Sprintf(
		"Update Go %s-%s %s",
		c.Repo.Owner,
		c.Repo.Name,
		c.ShortSHA(),
	)
}

// BuildCreateCommand assembles the CreateTaskCommand for a Candidate carrying
// a non-empty VulnIDs list (the frozen 12-key contract — the 10 consumer keys
// keep their semantics byte-identical to github-update-go-watcher, plus the
// vuln payload vuln_count and vulns).
func BuildCreateCommand(c Candidate, cfg TaskConfig) task.CreateCommand {
	taskIDStr := DeriveVulnTaskID(c.Repo.Owner, c.Repo.Name, c.VulnIDs).String()
	return task.CreateCommand{
		Title:          ComputeTaskTitle(c),
		TaskIdentifier: agentlib.TaskIdentifier(taskIDStr),
		Frontmatter:    buildFrontmatter(c, taskIDStr, cfg),
		Body:           buildTaskBody(c),
	}
}

func buildFrontmatter(
	c Candidate,
	taskIDStr string,
	cfg TaskConfig,
) agentlib.TaskFrontmatter {
	return agentlib.TaskFrontmatter{
		"task_type":       "github-update-go",
		"assignee":        "github-update-go-agent",
		"phase":           "planning",
		"status":          "in_progress",
		"stage":           cfg.Stage,
		"task_identifier": taskIDStr,
		"title":           ComputeTaskTitle(c),
		"repo":            c.Repo.String(),
		"clone_url": fmt.Sprintf(
			"git@github.com:%s/%s.git",
			c.Repo.Owner,
			c.Repo.Name,
		),
		"ref":        c.HeadSHA,
		"vuln_count": len(c.VulnIDs),
		"vulns":      c.VulnIDs,
	}
}

func buildTaskBody(c Candidate) string {
	owner := c.Repo.Owner
	name := c.Repo.Name
	return fmt.Sprintf(
		"# Update Go: %s/%s\n\n"+
			"**Vulnerabilities:** %s\n"+
			"**HEAD:** %s\n"+
			"**Repo:** [%s/%s](https://github.com/%s/%s)\n",
		owner, name,
		strings.Join(c.VulnIDs, "  ·  "),
		c.ShortSHA(),
		owner, name, owner, name,
	)
}
