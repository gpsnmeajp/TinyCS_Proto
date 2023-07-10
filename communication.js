"use strict";

let relay;
let user_profiles = {};
let user_positions = {};
let mypubkey;

async function postMemo(text) {
    let event = {
        kind: 1,
        pubkey: mypubkey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: text
    }
    event.id = window.NostrTools.getEventHash(event)
    event = await window.nostr.signEvent(event);

    relay.publish(event)
}

async function onMemo(event) {
    const content = event.content;
}

async function postPosition(x, y, z) {
    const position = {
        x: x,
        y: y,
        z: z,
        v: ["TinyCS", "1.0.0"]
    };

    let event = {
        kind: 29420,
        pubkey: mypubkey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: JSON.stringify(position)
    }
    event.id = window.NostrTools.getEventHash(event)
    event = await window.nostr.signEvent(event);

    relay.publish(event)
}

async function onPosition(event) {
    const content = JSON.parse(event.content);

    // プロトコルバージョンチェック
    if (content.v === undefined) {
        return;
    }
    if (content.v[0] !== "TinyCS") {
        return;
    }
    if (content.v[1] !== "1.0.0") {
        return;
    }

    // 座標に反映
    if (user_positions[event.pubkey] === undefined) {
        user_positions[event.pubkey] = {};
    }
    user_positions[event.pubkey].x = content.x;
    user_positions[event.pubkey].y = content.y;
    user_positions[event.pubkey].z = content.z;
}

function getProfile(pubkey) {
    // 一旦初期値で埋めておく
    if(user_profiles[pubkey] == undefined) {
        user_profiles[pubkey] = {
            name: pubkey,
            picture: ""
        };
    }

    return new Promise((resolve, reject) => {
        // リレーに取得を依頼する
        let psub = relay.sub([
            {
                kinds: [0],
                limit: 1,
                authors: [pubkey]
            }
        ]);
        psub.on('event', event => {
            if (event.kind === 0) {
                // プロフィールイベント
                psub.unsub();
                onProfile(event);
                resolve();
            }
        });
        psub.on('eose', () => {
            psub.unsub();
            resolve();
        });
    });
}

function onProfile(event) {
    const content = JSON.parse(event.content);
    user_profiles[event.pubkey] = {
        name: content.name,
        picture: content.picture
    };
}


async function connectRelay() {
    if(window.nostr == undefined){
        setStatus("⚠ NIP-07 not found!");
        return;
    }
    mypubkey = await window.nostr.getPublicKey();

    // リレーに接続する
    relay = window.NostrTools.relayInit('wss://relay-jp.nostr.wirednet.jp');
    relay.on('connect', () => {
        setStatus(`connected to ${relay.url}`)
    });
    relay.on('error', () => {
        setStatus(`failed to connect to ${relay.url}`)
    });

    await relay.connect();

    // リレーから必要な情報を購読する
    let sub = relay.sub([
        {
            kinds: [0, 1, 29420],
            since: Math.round(Date.now() / 1000) - 15 * 60 // 15分前まで取得
        }
    ]);
    sub.on('event', async event => {
        if (event.kind === 29420) {
            // 位置情報イベント
            onPosition(event);
        }

        if (event.kind === 1) {
            // メモイベント
            onMemo(event);
        }

        if (event.kind === 0) {
            // プロフィールイベント
            onProfile(event);
        }
        let name = "unknown";
        if(user_profiles[event.pubkey] == undefined) {
            await getProfile(event.pubkey);
        }
        if(user_profiles[event.pubkey] != undefined) {
            name = user_profiles[event.pubkey].name
        }
        addLog("[" + name + "] " + JSON.stringify(event));
    });
}