<h1 align="center">
  <a href="https://pion.ly"><img src="./.github/pion-gopher-webrtc.png" alt="Pion WebRTC" height="250px"></a>
  <br>
  Pion Quic
  <br>
</h1>
<h4 align="center">A pure Go implementation of the WebRTC API</h4>
<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-webrtc-gray.svg?longCache=true&colorB=brightgreen" alt="Pion WebRTC"></a>
  <a href="https://sourcegraph.com/github.com/pion/quic?badge"><img src="https://sourcegraph.com/github.com/pion/quic/-/badge.svg" alt="Sourcegraph Widget"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="join us on Discord"></a> <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a> <a href="https://twitter.com/_pion?ref_src=twsrc%5Etfw"><img src="https://img.shields.io/twitter/url.svg?label=Follow%20%40_pion&style=social&url=https%3A%2F%2Ftwitter.com%2F_pion" alt="Twitter Widget"></a>
  <a href="https://github.com/pion/awesome-pion" alt="Awesome Pion"><img src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg"></a>
  <br>
  <img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/pion/quic/test.yaml">
  <a href="https://pkg.go.dev/github.com/pion/quic"><img src="https://pkg.go.dev/badge/github.com/pion/quic.svg" alt="Go Reference"></a>
  <a href="https://codecov.io/gh/pion/quic"><img src="https://codecov.io/gh/pion/quic/branch/master/graph/badge.svg" alt="Coverage Status"></a>
  <a href="https://goreportcard.com/report/github.com/pion/quic"><img src="https://goreportcard.com/badge/github.com/pion/quic" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<br>

An work in progress experimental QUIC API that implements:
- QUIC API wrapper Peer-to-peer and server/clients communications.
- [draft-ietf-webtrans-http3-14](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)

The library doesn't implement the QUIC protocol itself. It relies on [quic-go](https://github.com/quic-go/quic-go ) for this purpose.

-----


### Need Help?
Check out [WebRTC for the Curious](https://webrtcforthecurious.com). A book about WebRTC in depth, not just about the APIs.
Learn the full details of ICE, SCTP, DTLS, SRTP, and how they work together to make up the WebRTC stack. This is also a great
resource if you are trying to debug. Learn the tools of the trade and how to approach WebRTC issues. This book is vendor
agnostic and will not have any Pion specific information.

Pion has an active community on [Discord](https://discord.gg/PngbdqpFbt). Please ask for help about anything, questions don't have to be Pion specific!
Come share your interesting project you are working on. We are here to support you.

#### Pure Go
* No Cgo usage
* Wide platform support
  * Windows, macOS, Linux, FreeBSD
  * iOS, Android
  * [WASM](https://github.com/pion/webrtc/wiki/WebAssembly-Development-and-Testing) see [examples](examples/README.md#webassembly)
  *  386, amd64, arm, mips, ppc64
* Easy to build *Numbers generated on Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz*
  * **Time to build examples/play-from-disk** - 0.66s user 0.20s system 306% cpu 0.279 total
  * **Time to run entire test suite** - 25.60s user 9.40s system 45% cpu 1:16.69 total
* Tools to measure performance [provided](https://github.com/pion/rtsp-bench)

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
