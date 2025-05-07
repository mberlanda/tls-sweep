# Tls-Sweep

Some website rotate their first party domain without leaving traces or redirections. Sometimes old domain are still accessible but cerficates get detached.

This package provide an utility to retrieve all top-level domains as per IANA specifications, and iterate over them to check the availability of a base domain, and present the findings in a table of valid domains resolved.

### Usage

```
go build main.go
./tls-sweep <base-domain> > <base-domain>.md
```

E.g. `./tls-sweep amazon > amazon-domains.md`
