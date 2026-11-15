# modemctl

Command-line client for the web API of the ZTE MC888x 5G router. It talks to the same
`/goform` endpoints as the router's web UI, so anything the UI can read or change can be
done from a terminal or a script.

Single Go file, standard library only. Tested on one device: an MC888x with firmware
`BD_ORDTNG5CV1.0.0B07`. Other ZTE routers that use the goform API with SHA256 login may
work; none were tried.

## Install

Requires Go and macOS (the password is read from the macOS keychain).

```sh
git clone https://github.com/kidkuddy/modemctl
cd modemctl
go build -o modemctl .
```

Store the router's admin password in the keychain once. The command prompts for it:

```sh
security add-generic-password -s modem-admin -a password -w
```

## Usage

```
modemctl status                     signal / network / WAN summary
modemctl devices                    connected Wi-Fi and LAN clients, as a table
modemctl name MAC NAME              give a device a name on the modem
modemctl ussd CODE [REPLY...]       run a USSD code (e.g. '*111#'), then answer its menus
modemctl sms                        list SMS
modemctl sms send NUMBER TEXT       send SMS
modemctl sms rm ID [ID...]          delete SMS
modemctl get NV[,NV...] [k=v...]    read any variable(s), raw JSON
modemctl set GOFORM_ID [k=v...]     run any write action, raw JSON
modemctl ids                        list every NV name / GOFORM_ID the web UI uses
modemctl reboot | logout
```

| Variable | Default | Meaning |
|---|---|---|
| `MODEM_HOST` | `192.168.1.1` | router address |
| `MODEM_USER` | `User` | web UI user name |

### Devices

```
$ modemctl devices
NAME            IP             MAC                LINK         NOTE
Living-room-TV  192.168.1.20   AA:BB:CC:00:11:22  ethernet
--              192.168.1.31   D6:00:00:00:00:01  wifi 2.4GHz  private (randomized) MAC
```

`--` means the device announced no hostname. Give it one, stored on the router:

```sh
modemctl name D6:00:00:00:00:01 "Kitchen-tablet"
```

A phone with a private (randomized) MAC gets a new address when it forgets and rejoins the
network; the saved name does not follow it.

### Everything else: `get` and `set`

The named commands cover a small part of the API. `modemctl ids` downloads the web UI's
JavaScript from the router and lists every variable it reads (about 690) and every write
action it sends (about 180). Any of them can be used directly:

```sh
modemctl get wifi_chip1_ssid1_ssid,wifi_chip2_ssid1_ssid
modemctl set SET_WEB_LANGUAGE Language=en
```

Parameters for a write action are not documented by the router. Find them by searching for
the action's name in `http://192.168.1.1/js/service.js`.

## What was tested

| Command | State |
|---|---|
| `status`, `devices`, `name`, `sms`, `get`, `ids`, `logout` | run against the router |
| `set` | write path exercised through `name` and `logout` |
| `sms send`, `sms rm`, `reboot` | not run; request shapes are taken from the web UI's code |
| `ussd` | the router accepts the request, but on the test SIM the network never answered and it timed out |

`sms send` always uses Unicode encoding, which limits one segment to 70 characters. SMS and
USSD go through the SIM in the router and are billed by its mobile plan.

## How it works

- **Read:** `GET /goform/goform_get_cmd_process?cmd=a,b,c&multi_data=1` returns the named
  variables as JSON.
- **Write:** `POST /goform/goform_set_cmd_process` with `goformId=ACTION` plus parameters.
- **Login:** `goformId=LOGIN_MULTI_USER` with
  `password = SHA256(SHA256(password) + LD)` in uppercase hex, where `LD` is a per-login
  value read from the router. The response sets a `stok` session cookie.
- **Write token:** every write needs `AD = md5(md5(cr_version + wa_inner_version) + RD)`,
  where `RD` is a one-time value read just before the write.
- **Session:** the cookie is cached in `~/.cache/modemctl/stok` (mode 0600). The router
  ends a session after 5 minutes idle and allows one session at a time, so logging in to
  the web UI logs the CLI out and the reverse; the CLI logs in again when that happens.
- Every request needs a `Referer` header pointing at the router, or it is rejected.

The router locks the login after 5 wrong passwords. A failed login prints how many
attempts remain.

## Development

```sh
go vet ./... && go test ./...
```
