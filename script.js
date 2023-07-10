"use strict";

// python -m http.server
// http://localhost:8000/

let app = new PIXI.Application({ width: 800, height: 800 });
let state_x = 0;
let state_y = 0;
let relay;

let users = {};

function setStatus(s) {
    document.getElementById('status').innerText = s;
}
function setMyPos(x, y, state_x, state_y) {
    document.getElementById('pos').innerText = "(" + x + "," + y + ") [" + state_x + "," + state_y + "]";

    let content = {
        x: x,
        y: y,
        sx: state_x,
        sy: state_y
    };

    (async () => {
        const pk = await window.nostr.getPublicKey();
        let event = {
            kind: 29420,
            pubkey: pk,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: JSON.stringify(content)
        }
        event.id = window.NostrTools.getEventHash(event)
        event = await window.nostr.signEvent(event);

        console.log("send...", event);
        relay.publish(event)
    })();
}
function addLog(s) {
    document.getElementById('log').innerText = new Date() + " : " + s + '\n' + document.getElementById('log').innerText;
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp') {
        state_y = -1;
    }
    if (e.key === 'ArrowDown') {
        state_y = 1;
    }
    if (e.key === 'ArrowLeft') {
        state_x = -1;
    }
    if (e.key === 'ArrowRight') {
        state_x = 1;
    }
});
document.addEventListener('keyup', (e) => {
    if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        state_y = 0;
    }
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        state_x = 0;
    }
});

window.addEventListener('load', async (e) => {
    document.getElementById('screen').appendChild(app.view);
    let sprite = new PIXI.Text('X', {
        fontFamily: 'Arial',
        fontSize: 12,
        fill: 0xFFFFFF,
        align: 'center',
    });
    sprite.anchor.set(0.5);
    app.stage.addChild(sprite);

    let old_state_x = 0;
    let old_state_y = 0;
    app.ticker.add((delta) => {
        if (state_x !== old_state_x || state_y !== old_state_y) {
            old_state_x = state_x;
            old_state_y = state_y;

            setMyPos(sprite.x, sprite.y, state_x, state_y);
        }

        sprite.y += state_y;
        sprite.x += state_x;

        for(const c in users){
            let user = users[c];
            user.sprite.x = user.content.x;
            user.sprite.y = user.content.y;

            // ステートに基づく予測座標更新
            user.content.x += user.content.sx;
            user.content.y += user.content.sy;
        }
    });
    // --------------------------------------------------------------------

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
            kinds: [29420],
            since: Math.round(Date.now() / 1000)
        }
    ])
    sub.on('event', event => {
        if(users[event.pubkey] === undefined){
            users[event.pubkey] = {
                sprite: new PIXI.Text(event.pubkey, {
                    fontFamily: 'Arial',
                    fontSize: 12,
                    fill: 0xFFFFFF,
                    align: 'center',
                })
            };
            users[event.pubkey].sprite.anchor.set(0.5);
            app.stage.addChild(users[event.pubkey].sprite);    
        }
        users[event.pubkey].content = JSON.parse(event.content);

        addLog(JSON.stringify(event));
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