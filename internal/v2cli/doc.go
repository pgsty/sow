// Package v2cli defines SOW's closed command grammar, human output, stable exit
// codes, and versioned JSON envelope.
//
// Human output is intentionally descriptive rather than an unversioned machine
// contract. Automation must request --json and consume sow.cli/v1. Failure
// envelopes retain results only when work or diagnostic evidence is meaningful;
// discovery, configuration, and usage failures return a null result.
package v2cli
