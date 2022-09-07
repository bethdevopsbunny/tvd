# tvl 
## tenable vulnerability linter

Reads the last 2 scans results and warns on increases to vulnerabilities. 


### use
`-critical <bool>` - if set to false will omit critical results (default true)<br>
`-exit-with-error <bool>` - returns errorcode 1 if increase to vulnerabilities <br>
`-high <bool>` - if set to false will omit high results (default true) <br>
`-low <bool>` - if set to false will omit low results (default true) <br>
`-medium <bool>` - if set to false will omit medium results (default true) <br>
`-scan-name <string>` - Target scan you wish to compare <br>
`-verbose <int>` - Displays Logging 1 or 2 for light or heavy log output <br>
