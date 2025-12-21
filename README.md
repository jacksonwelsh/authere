# Authere

Authentication and authorization software for web services.

## Goals

- [ ] Forward-auth support (specifically targeting Caddy)
- [ ] Very basic LDAP support
  - Not intended to be a full server at all, but should be complete enough to support Jellyfin
- [ ] Full OAuth2 support
- [ ] Web management UI
  - Not set on how this will be built, but goal is to completely embed this within the binary

## Motivations

Authere is a personal project I'm building, with the goal of replacing my use of [Authentik](https://goauthentik.io) in
my homelab. My goal here is to create a lightweight authn/z service in Rust with a web management UI that works well on
mobile and desktop (probably using Svelte, but that will come later).

Why do this at all? I'm looking to deepen my understanding of authentication schemes and learn some Rust while I'm at
it. With that, I expect to take some shortcuts - at least at first - to allow myself to focus on those aspects.

More information on goals here to come later, first let's just get some code out.
