---
name: roadmap-export
description: Publish the public roadmap from local beads. Use after creating, updating or closing beads issues in this repository, or when asked to update the public roadmap.
---

# Export the public roadmap

The beads database stays local; only a filtered JSONL export is public.

1. Make sure personal issues carry the `personal` label (anything about writing, the newsletter, career). When unsure, label it `personal`.
2. Export everything: `bd export -o /tmp/svid-all.jsonl`.
3. Filter and write the public file:

```python
import json
out = []
for line in open("/tmp/svid-all.jsonl"):
    issue = json.loads(line)
    if "personal" in (issue.get("labels") or []):
        continue
    issue.pop("owner", None)
    out.append(issue)
with open(".beads/issues.jsonl", "w") as f:
    f.writelines(json.dumps(i, ensure_ascii=False) + "\n" for i in out)
```

4. Check: `grep -c '@' .beads/issues.jsonl` prints 0, and no issue mentions personal topics.
5. Delete `/tmp/svid-all.jsonl`.
6. Commit with `git add -f .beads/issues.jsonl` (the global gitignore hides `.beads/`) and message `chore: Update the public roadmap`.
