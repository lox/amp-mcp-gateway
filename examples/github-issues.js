// Replace OWNER/SANDBOX-REPO here and in github-issues.json before installing.
const path = "/repos/OWNER/SANDBOX-REPO/issues";

function issue(value) {
  return { number: value.number, title: value.title, url: value.html_url };
}

export async function listIssues(args, ctx) {
  const response = await ctx.http.request({
    method: "GET", path, query: { state: args.state ?? "open", per_page: "20" },
    headers: { Accept: "application/vnd.github+json" }
  });
  if (response.status !== 200) throw new Error("List issues failed");
  return response.body.map(issue);
}

export async function createIssue(args, ctx) {
  const response = await ctx.http.request({
    method: "POST", path,
    headers: { Accept: "application/vnd.github+json" },
    body: { title: args.title, body: args.body ?? "" }
  });
  if (response.status !== 201) throw new Error("Create issue failed");
  return issue(response.body);
}
