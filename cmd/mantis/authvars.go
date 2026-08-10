package main

import "strings"

// authVars exposes resolved authentication as template/smoke/API variables
// so a template can just write `Authorization: Bearer ${MANTIS_TOKEN}`
// instead of needing to know how the environment's auth actually got
// resolved.
func authVars(headers map[string]string) map[string]string {
	vars := map[string]string{}
	if v, ok := headers["Authorization"]; ok {
		vars["MANTIS_AUTH_HEADER"] = v
		if strings.HasPrefix(v, "Bearer ") {
			vars["MANTIS_TOKEN"] = strings.TrimPrefix(v, "Bearer ")
		}
	}
	return vars
}

func mergeVars(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
