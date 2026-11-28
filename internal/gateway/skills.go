package gateway

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"
)

const skillsExtension = "io.modelcontextprotocol/skills"

//go:embed skills
var skillFiles embed.FS

// These wire types implement the Skills extension (SEP-2640), which is not yet
// built into the SDK. Requests still use the SDK's dispatch and middleware.
type skillResource struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
	Size   int    `json:"size"`
}

type skillEntry struct {
	URI         string          `json:"uri"`
	Frontmatter map[string]any  `json:"frontmatter"`
	Resources   []skillResource `json:"resources"`
}

type listSkillsParams struct {
	mcp.ParamsBase
	Cursor string `json:"cursor,omitempty"`
}

type listSkillsResult struct {
	mcp.ResultBase
	mcp.Cacheable
	ResultType string       `json:"resultType"`
	Skills     []skillEntry `json:"skills"`
}

type getSkillParams struct {
	mcp.ParamsBase
	URI string `json:"uri"`
}

type getSkillResult struct {
	mcp.ResultBase
	mcp.Cacheable
	ResultType string     `json:"resultType"`
	Skill      skillEntry `json:"skill"`
}

type bundledSkill struct {
	entry skillEntry
	files map[string]string
}

// Embedded authoring errors are programming errors, like invalid AddTool schemas.
var skillCatalog = func() []bundledSkill {
	entries, err := fs.ReadDir(skillFiles, "skills")
	if err != nil {
		panic(err)
	}
	var catalog []bundledSkill
	for _, dir := range entries {
		root := "skills/" + dir.Name()
		skill := bundledSkill{entry: skillEntry{URI: "skill://" + dir.Name() + "/SKILL.md"}, files: make(map[string]string)}
		err := fs.WalkDir(skillFiles, root, func(file string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := skillFiles.ReadFile(file)
			if err != nil {
				return err
			}
			uri := "skill://" + strings.TrimPrefix(file, "skills/")
			skill.files[uri] = string(data)
			skill.entry.Resources = append(skill.entry.Resources, skillResource{URI: uri, Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(data)), Size: len(data)})
			return nil
		})
		if err != nil {
			panic(err)
		}
		frontmatter, _, ok := strings.Cut(strings.TrimPrefix(skill.files[skill.entry.URI], "---\n"), "\n---\n")
		if !ok {
			panic("missing skill frontmatter: " + root)
		}
		if err := yaml.Unmarshal([]byte(frontmatter), &skill.entry.Frontmatter); err != nil {
			panic(err)
		}
		if skill.entry.Frontmatter["name"] != dir.Name() || skill.entry.Frontmatter["description"] == nil {
			panic("invalid skill frontmatter: " + root)
		}
		catalog = append(catalog, skill)
	}
	return catalog
}()

func (g *Gateway) registerSkills(s *mcp.Server) {
	err := mcp.AddReceivingCustomMethod(s, "skills/list", func(_ context.Context, _ *mcp.ServerSession, params *listSkillsParams) (*listSkillsResult, error) {
		if params != nil && params.Cursor != "" {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "invalid skills cursor"}
		}
		out := &listSkillsResult{ResultType: "complete", Cacheable: mcp.Cacheable{CacheScope: "private"}, Skills: []skillEntry{}}
		for _, skill := range skillCatalog {
			out.Skills = append(out.Skills, skill.entry)
		}
		return out, nil
	})
	if err != nil {
		panic(err)
	}
	err = mcp.AddReceivingCustomMethod(s, "skills/get", func(_ context.Context, _ *mcp.ServerSession, params *getSkillParams) (*getSkillResult, error) {
		if params != nil {
			for _, skill := range skillCatalog {
				if skill.entry.URI == params.URI {
					return &getSkillResult{ResultType: "complete", Cacheable: mcp.Cacheable{CacheScope: "private"}, Skill: skill.entry}, nil
				}
			}
		}
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "skill unavailable"}
	})
	if err != nil {
		panic(err)
	}
	// Only a generic template is listed; each skill's manifest lists its files.
	s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "skill://{+file}", Name: "Gateway skill file", MIMEType: "text/markdown"}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		for _, skill := range skillCatalog {
			if text, ok := skill.files[req.Params.URI]; ok {
				return &mcp.ReadResourceResult{Cacheable: mcp.Cacheable{CacheScope: "private"}, Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/markdown", Text: text}}}, nil
			}
		}
		return nil, mcp.ResourceNotFoundError(req.Params.URI)
	})
}
