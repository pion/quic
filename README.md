<h1 align="center">
  Pion QUIC
</h1>
<h4 align="center">A pure Go implementation of a QUIC API</h4>
<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-quic-gray.svg?longCache=true&colorB=brightgreen" alt="Pion QUIC"></a>
  <a href="https://sourcegraph.com/github.com/pion/quic?badge"><img src="https://sourcegraph.com/github.com/pion/quic/-/badge.svg" alt="Sourcegraph Widget"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="join us on Discord"></a> <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a> <a href="https://twitter.com/_pion?ref_src=twsrc%5Etfw"><img src="https://img.shields.io/twitter/url.svg?label=Follow%20%40_pion&style=social&url=https%3A%2F%2Ftwitter.com%2F_pion" alt="Twitter Widget"></a>
  <br>
  <img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/pion/quic/test.yaml">
  <a href="https://pkg.go.dev/github.com/pion/quic"><img src="https://pkg.go.dev/badge/github.com/pion/quic.svg" alt="Go Reference"></a>
  <a href="https://codecov.io/gh/pion/quic"><img src="https://codecov.io/gh/pion/quic/branch/master/graph/badge.svg" alt="Coverage Status"></a>
  <a href="https://goreportcard.com/report/github.com/pion/quic"><img src="https://goreportcard.com/badge/github.com/pion/quic" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<br>

An work in progress experimental QUIC API that implements:
- QUIC API wrapper for Peer-to-peer and server/clients communications.
- [draft-ietf-webtrans-http3-14](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)

The library doesn't implement the QUIC protocol itself. It relies on [quic-go](https://github.com/quic-go/quic-go ) for this purpose.

-----

### Roadmap
The library is in active development, a readmap is coming soon.

### Community
Pion has an active community on the [Discord](https://discord.gg/PngbdqpFbt).

Follow the [Pion Bluesky](https://bsky.app/profile/pion.ly) or [Pion Twitter](https://twitter.com/_pion) for project updates and important WebRTC news.

We are always looking to support **your projects**. Please reach out if you have something to build!
If you need commercial support or don't want to use public methods you can contact us at [team@pion.ly](mailto:team@pion.ly)

### Contributing
Check out the [contributing wiki](https://github.com/pion/webrtc/wiki/Contributing) to join the group of amazing people making this project possible

### License
MIT License - see [LICENSE](LICENSE) for full text
