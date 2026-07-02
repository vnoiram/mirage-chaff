// Package policy loads policy.d/*.yaml and matches requests by domain+path+method
// (priority-ordered), selecting an action: stub, forward-scrubbed, forward-mimic,
// forward-asis, or passthrough. Reloads are validate-then-swap (design doc D-2).
package policy
