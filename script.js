"use strict";

// python -m http.server
// http://localhost:8000/

let relay;

function setStatus(s) {
    document.getElementById('status').innerText = s;
}
function addLog(s) {
    document.getElementById('log').innerText += s + '\n';
}

window.addEventListener('load', async (e) => {
    relay = window.NostrTools.relayInit('wss://relay-jp.nostr.wirednet.jp')
    relay.on('connect', () => {
        setStatus(`connected to ${relay.url}`)
    })
    relay.on('error', () => {
        setStatus(`failed to connect to ${relay.url}`)
    })

    await relay.connect()

    // let's query for an event that exists
    let sub = relay.sub([
        {
            kinds: [1],
            since: Math.round(Date.now() / 1000)
            // ids: ['d7dd5eb3ab747e16f8d0212d53032ea2a7cadef53837e5a6c66d42849fcb9027']
        }
    ])
    sub.on('event', event => {
        addLog(event.content);
    })
    sub.on('eose', () => {
        // sub.unsub()
    })

    document.getElementById("send_button").addEventListener('click', async (e) => {
        const pk = await window.nostr.getPublicKey();
        let event = {
            kind: 1,
            pubkey: pk,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: 'nostr-toolsでとりあえず投稿できるようになった。NIP-07は気楽でいいな'
        }
        event.id = window.NostrTools.getEventHash(event)
        event = await window.nostr.signEvent(event);

        console.log("send...", event);
        relay.publish(event)
    });

});