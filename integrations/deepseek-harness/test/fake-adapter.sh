#!/usr/bin/env bash
set -euo pipefail

while IFS= read -r line; do
  request_id="$(sed -n 's/.*\"request_id\":\"\([^\"]*\)\".*/\1/p' <<<"${line}")"
  command="$(sed -n 's/.*\"command\":\"\([^\"]*\)\".*/\1/p' <<<"${line}")"
  if [[ "${command}" == delay-command ]]; then
    sleep 2
    printf '{"schema_version":1,"request_id":"%s","decision":"allow"}\n' "${request_id}"
  elif [[ "${command}" == crash-command ]]; then
    exit 42
  elif [[ "${command}" == invalid-command ]]; then
    printf 'not-json\n'
  elif [[ "${command}" == invalid-shape-command ]]; then
    printf '{"schema_version":1,"request_id":"%s","decision":"wat"}\n' "${request_id}"
  elif [[ "${command}" == extra-field-command ]]; then
    printf '{"schema_version":1,"request_id":"%s","decision":"allow","extra":true}\n' "${request_id}"
  elif [[ "${command}" == policy-root-command ]]; then
    if [[ "${line}" == *'"cwd":"/policy/sub"'* && "${line}" == *'"workspace_root":"/policy"'* ]]; then
      printf '{"schema_version":1,"request_id":"%s","decision":"allow"}\n' "${request_id}"
    else
      printf '{"schema_version":1,"request_id":"%s","error":"policy workspace mismatch"}\n' "${request_id}"
    fi
  elif [[ "${command}" == deny-command ]]; then
    printf '{"schema_version":1,"request_id":"%s","decision":"deny","reason":"[Caushell] test deny"}\n' "${request_id}"
  elif [[ "${command}" == ask-command ]]; then
    printf '{"schema_version":1,"request_id":"%s","decision":"ask","reason":"[Caushell] test ask"}\n' "${request_id}"
  else
    printf '{"schema_version":1,"request_id":"%s","decision":"allow"}\n' "${request_id}"
  fi
done
