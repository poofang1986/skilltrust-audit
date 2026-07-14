# Policy Overrides

Use a JSON object with only the fields that need changing:

```json
{
  "max_file_bytes": 500000,
  "max_text_lines": 5000,
  "allowed_opaque_paths": ["assets/logo.png"],
  "ignored_paths": ["vendor/reviewed-library"],
  "approved_registry_domains": ["registry.npmjs.org", "pypi.org"]
}
```

Paths are relative to the audit target. Directory entries match their descendants.

Do not use `ignored_paths` for convenience. An ignored path is outside the audit evidence and must be reviewed through another explicit process. Prefer an exact `allowed_opaque_paths` entry for a necessary image or document.

Keep the policy beside the Skill and include it in the integrity manifest.
