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

function upRGB(code){
    let r = parseInt(code.substring(0, 2), 16)
    let g = parseInt(code.substring(2, 4), 16)
    let b = parseInt(code.substring(4, 6), 16)

    r += 0x7F;
    if(r>0xFF){r=0xFF;};
    g += 0x7F;
    if(g>0xFF){g=0xFF;};
    b += 0x7F;
    if(b>0xFF){b=0xFF;};

    return r<<16 | g<<8 | b;
}

async function onMemo(event) {
    let content = event.content;
    content = content.replace(/(?:https?|ftp):\/\/[\n\S]+/g, ''); //URLを削除
    content = content.replace(/(?:nostr):[\n\S]+/g, ''); //nostr:を削除

    if (event.pubkey == mypubkey) {
        player_text_sprite.text = content;
        player.created_at = event.created_at;
        return;
    }

    let sprite = new PIXI.Text(content, {
        fontFamily: 'Arial',
        fontSize: 12,
        fill: upRGB(event.pubkey),
        align: 'center',
        wordWrap: true,
        wordWrapWidth: 200,
        breakWords: true,
    });
    sprite.anchor.set(0.5, 0);

    let picture = "unknown.png"
    if (user_profiles[event.pubkey].picture != "") {
        picture = user_profiles[event.pubkey].picture;
    }
    const sprite2 = PIXI.Sprite.from(picture);
    sprite2.width = 24;
    sprite2.height = 24;
    sprite2.anchor.set(0.5, 1.0);

    let x = (parseInt(event.sig.substring(0, 3), 16) - 0x800) /4; //次の目標座標
    let y = (parseInt(event.sig.substring(3, 6), 16) - 0x800) /4;
    let ox = x; //旧座標
    let oy = y;

    if (others[event.pubkey] != undefined) {
        app.stage.removeChild(others[event.pubkey].text_sp);
        app.stage.removeChild(others[event.pubkey].icon_sp);
        ox = others[event.pubkey].x;
        oy = others[event.pubkey].y;
    }
    others[event.pubkey] = { tx: x, ty: y, x: ox, y: oy, text_sp: sprite, icon_sp: sprite2, created_at: event.created_at};
    app.stage.addChild(sprite);
    app.stage.addChild(sprite2);
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
    let content;
    try {
        content = JSON.parse(event.content);
    } catch (e) {
        return;
    }

    // プロトコルバージョンチェック
    if (content === undefined) {
        return;
    }
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
    if (user_profiles[pubkey] == undefined) {
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


async function connectRelay(relay_adr) {
    if (window.nostr == undefined) {
        setStatus("⚠ NIP-07 not found!");
        return;
    }

    // リレーの情報を確認する
    try {
        const nip11 = await (await fetch(relay_adr.replace("wss://", "https://"), { headers: { "Accept": "application/nostr+json" } })).json();
        console.log(nip11);
        if (!nip11["supported_nips"].includes(16)) {
            setStatus("⚠ This relay does not supported NIP-16!");
            return;
        }
    } catch (e) {
        setStatus("⚠ " + e);
        return;
    }

    return new Promise(async (resolve, reject) => {
        mypubkey = await window.nostr.getPublicKey();

        // リレーに接続する
        relay = window.NostrTools.relayInit(relay_adr);
        relay.on('connect', async () => {
            setStatus(`connected to ${relay.url}`)

            // 自己Profileを取得
            await getProfile(mypubkey);
            resolve(mypubkey);
        });
        relay.on('error', () => {
            setStatus(`failed to connect to ${relay.url}`)
        });

        await relay.connect();

        // リレーから必要な情報を購読する
        let sub = relay.sub([
            {
                kinds: [0, 1, 29420],
                since: Math.round(Date.now() / 1000) - 3600 // 1時間前まで取得
            }
        ]);
        sub.on('event', async event => {
            if (user_profiles[event.pubkey] == undefined) {
                await getProfile(event.pubkey);
            }

            if (event.kind === 29420) {
                // 位置情報イベント
                onPosition(event);
            }

            if (event.kind === 1) {
                // メモイベント
                onMemo(event);

                let name = "unknown";
                if (user_profiles[event.pubkey] != undefined) {
                    name = user_profiles[event.pubkey].name
                }
                addLog("[" + name + "] " + event.content);
            }

            if (event.kind === 0) {
                // プロフィールイベント
                onProfile(event);
            }
        });
    });
}