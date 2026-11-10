<h1 align="center">
  <br>
  Pion QUIC
  <br>
</h1>
<h4 align="center">An experimental QUIC implementation in Go, built from Pion DTLS</h4>
<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-quic-gray.svg?longCache=true&colorB=brightgreen" alt="Pion QUIC"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="join us on Discord"></a> <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a>
  <br>
  <img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/pion/quic/test.yaml">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<br>

> [!WARNING]
> This project is experimental. Its API, wire behavior, and module path will
> change without notice. Do not use it in production.

Pion QUIC is an experiment in modifying [Pion DTLS][pion-dtls] into a QUIC
implementation. It builds on the DTLS 1.3 handshake, record protection, key
updates, connection IDs, and path migration that already exist in this code.

### Goals

* A focused QUIC stack for **media servers and IoT servers**, where datagrams,
  low latency, small footprints, and control over congestion and pacing matter
  more than broad HTTP compatibility.
* A place for **QUIC in WebRTC**, for example running QUIC on the ICE
  transport next to or in place of DTLS/SCTP, and
  [RTP over QUIC (RoQ)][roq].

### Non-goals

* A general-purpose QUIC library. For that, use [quic-go][quic-go].
* Generic HTTP/3, we we'll eventually support a small subset of WebTransport.

### Background

* Mathis Engelbart, Fabian Willi Fromwald, and Jörg Ott.
  [*QUIC as Multiplexing Layer in WebRTC*][quic-webrtc-paper].
  Applied Networking Research Workshop (ANRW '26), Vienna, July 2026.
* [RFC 9443: Multiplexing Scheme Updates for QUIC][rfc9443], which defines how
  QUIC shares a port with STUN, TURN, DTLS, and RTP.
* [RTP over QUIC (RoQ)][roq], an IETF AVTCORE draft.

[pion-dtls]: https://github.com/pion/dtls
[quic-go]: https://github.com/quic-go/quic-go
[quic-webrtc-paper]: https://researchr.org/publication/EngelbartFO26
[rfc9443]: https://www.rfc-editor.org/rfc/rfc9443
[roq]: https://datatracker.ietf.org/doc/draft-ietf-avtcore-rtp-over-quic/

### License
MIT License - see [LICENSE](LICENSE) for full text
