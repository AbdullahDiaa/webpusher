<p align="center" width="100%">
     <img alt="GOWebPusher - Push notifications for the web browsers using Golang" src=".github/logo.png"> 
</p>

# GoWebPusher

[![GoDoc][godoc-image]][godoc-url]
[![codecov](https://codecov.io/gh/AbdullahDiaa/GoWebPusher/branch/main/graph/badge.svg?token=70SJB4GC8E)](https://codecov.io/gh/AbdullahDiaa/GoWebPusher)
[![Build Status](https://travis-ci.com/AbdullahDiaa/GoWebPusher.svg?token=xpANNwyiLEp99ynBzKhp&branch=main)](https://travis-ci.com/AbdullahDiaa/GoWebPusher)

> Push notifications for the web browsers using Golang

> ⚠️ Library still under active development 

## Features
* [ ] Send push notifications to web browsers


## Supported browsers

<table>
<thead>
<tr>
<th><strong>Browser</strong></th>
<th><strong>Supported version</strong></th>
<th><strong>Endpoint</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Chrome</td>

<td>✓ 60+</td>

<td><code>https://fcm.googleapis.com/fcm/send/{subId}</code></td>
</tr>

<tr>
<td>Edge</td>

<td>✓ 17+</td>

<td><code>https://par02p.notify.windows.com/w/?token={subId}</code></td>
</tr>

<tr>
<td>Firefox</td>

<td>✓ 55+</td>

<td><code>https://updates.push.services.mozilla.com/wpush/v2/{subId}</code></td>
</tr>

<tr>
<td>Vivaldi</td>

<td>✓ 17+</td>

<td><code>https://fcm.googleapis.com/fcm/send/{subId}</code></td>
</tr>


<tr>
<td>Opera</td>

<td>✓ 76+</td>

<td><code>https://fcm.googleapis.com/fcm/send/{subId}</code></td>

</tr>


<tr>
<td>Yandex</td>

<td>✓ 21+</td>

<td><code>https://fcm.googleapis.com/fcm/send/{subId}</code></td>

</tr>

<tr>
<td>Safari</td>

<td>✗</td>

<td>Safari supports <a href="https://developer.apple.com/notifications/safari-push-notifications/" target="_blank">a custom implementation</a> .<br /> <a href="https://developer.apple.com/videos/play/wwdc2013/614/" target="_blank">WWDC video by apple</a></td>
</tr>

</tbody>
</table>

## Usage

```go
package main

func main() {

}

```

## Speed

..


## Documentation

You can view detailed documentation here: [GoDoc][godoc-url].

## Contributing

There are many ways to contribute:
- Fix and [report bugs](https://github.com/AbdullahDiaa/GoWebPusher/issues/new)
- [Improve documentation](https://github.com/AbdullahDiaa/GoWebPusher/issues?q=is%3Aopen+label%3Adocumentation)
- [Review code and feature proposals](https://github.com/AbdullahDiaa/GoWebPusher/pulls)


## Changelog

View the [changelog](/CHANGELOG.md) for the latest updates and changes by
version.

## License

[Apache License 2.0][licence-url]

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

[godoc-image]: https://godoc.org/github.com/AbdullahDiaa/GoWebPusher?status.svg
[godoc-url]: https://godoc.org/github.com/AbdullahDiaa/GoWebPusher
[licence-url]: https://github.com/AbdullahDiaa/GoWebPusher/blob/main/LICENSE