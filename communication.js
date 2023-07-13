"use strict";

let relay;
let user_profiles = {};
let user_positions = {};
let mypubkey;
let events = [];
let contacts = [];

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

function upRGB(code) {
    let r = parseInt(code.substring(0, 2), 16)
    let g = parseInt(code.substring(2, 4), 16)
    let b = parseInt(code.substring(4, 6), 16)

    r += 0x7F;
    if (r > 0xFF) { r = 0xFF; };
    g += 0x7F;
    if (g > 0xFF) { g = 0xFF; };
    b += 0x7F;
    if (b > 0xFF) { b = 0xFF; };

    return r << 16 | g << 8 | b;
}

async function onMemo(event) {
    let content = event.content;
    content = content.replace(/(?:https?|ftp):\/\/[\n\S]+/g, ''); //URLを削除
    content = content.replace(/(?:nostr):[\n\S]+/g, ''); //nostr:を削除

    let picture = "unknown.png"
    let contentWithName = content;
    if (user_profiles[event.pubkey].name != undefined) {
        contentWithName = user_profiles[event.pubkey].name + "\n" + content;
    }
    if (user_profiles[event.pubkey].picture != "") {
        picture = user_profiles[event.pubkey].picture;
    }

    if (event.pubkey == mypubkey) {
        player_text = contentWithName;
        player_text_sprite.text = contentWithName;
        player.created_at = event.created_at;
        return;
    }

    // 長すぎるやつは省略する
    if (contentWithName.length > 300) {
        contentWithName = contentWithName.substring(0, 300) + "…";
    }

    let sprite = new PIXI.Text(contentWithName, {
        fontFamily: 'Arial',
        fontSize: 12,
        fill: upRGB(event.pubkey),
        align: 'center',
        wordWrap: true,
        wordWrapWidth: 200,
        breakWords: true,
    });
    sprite.anchor.set(0.5, 0);


    const sprite2 = PIXI.Sprite.from(picture);
    sprite2.width = 24;
    sprite2.height = 24;
    sprite2.anchor.set(0.5, 1.0);

    let x = (parseInt(event.id.substring(6, 6 + 3), 16) - 0x800) / 2; //次の目標座標
    let y = (parseInt(event.id.substring(12, 12 + 3), 16) - 0x800) / 2;
    let ox = x; //旧座標
    let oy = y;

    if (others[event.pubkey] != undefined) {
        // テキストの管理を移動する(これにより古いテキストも表示されるようになる)
        others_text.push({ x: others[event.pubkey].rx, y: others[event.pubkey].ry, text_sp: others[event.pubkey].text_sp, created_at: others[event.pubkey].created_at });
        if (others_text.length > 1024) {
            var first = others_text.shift();
            first.text_sp.destroy();
        }

        others[event.pubkey].icon_sp.destroy();
        ox = others[event.pubkey].x;
        oy = others[event.pubkey].y;

        // 表示に反映
        internal_status.others_text = others_text.length;

    }
    //tx ターゲットx (次の表示位置)
    //x 現在位置x (表示位置)
    //rx ランダム位置原本x
    others[event.pubkey] = { tx: x, ty: y, x: ox, y: oy, rx: x, ry: y, text_sp: sprite, icon_sp: sprite2, created_at: event.created_at, text: contentWithName, name: user_profiles[event.pubkey].name };
    app.stage.addChild(sprite);
    app.stage.addChild(sprite2);

    // 表示に反映
    internal_status.others = Object.keys(others).length;
}

async function postPosition(x, y, z) {
    const position = {
        x: Math.floor(x),
        y: Math.floor(y),
        z: Math.floor(z),
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

async function postPositionPermanent(x, y, z) {
    const position = {
        x: Math.floor(x),
        y: Math.floor(y),
        z: Math.floor(z),
        v: ["TinyCS", "1.0.0"]
    };

    let event = {
        kind: 30078,
        pubkey: mypubkey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
            ["d", "TinyCS"],
        ],
        content: JSON.stringify(position)
    }
    event.id = window.NostrTools.getEventHash(event)
    event = await window.nostr.signEvent(event);

    relay.publish(event)
}

async function onPositionPermanent(event) {
    if (event["tags"][0] == undefined) {
        return;
    }
    if (event["tags"][0][0] != "d") {
        return;
    }
    if (event["tags"][0][1] != "TinyCS") {
        return;
    }
    onPosition(event);
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
    user_positions[event.pubkey].created_at = event.created_at;

    // 表示に反映
    internal_status.user_positions = Object.keys(user_positions).length;
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
        var timeout = setTimeout(resolve, 3000);
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
                clearTimeout(timeout);
            }
        });
        psub.on('eose', () => {
            psub.unsub();
            resolve();
            clearTimeout(timeout);
        });
    });
}

function onProfile(event) {
    const content = JSON.parse(event.content);
    user_profiles[event.pubkey] = {
        name: content.name,
        picture: content.picture
    };
    // 表示に反映
    internal_status.user_profiles = Object.keys(user_profiles).length;
}

function onReaction(event) {
    var target_pubkey;
    var target_id;
    var content = event.content.replace("+", "❤");
    var emoji = undefined;

    for (var t in event["tags"]) {
        if (event["tags"][t][0] == "p") {
            target_pubkey = event["tags"][t][1];
        }
        if (event["tags"][t][0] == "e") {
            target_id = event["tags"][t][1];
        }
        if (event["tags"][t][0] == "emoji") {
            emoji = event["tags"][t][2];
        }
    }

    let sprite;
    if (emoji == undefined) {
        sprite = new PIXI.Text(content, {
            fontFamily: 'Arial',
            fontSize: 24,
            fill: upRGB(event.pubkey),
            align: 'center',
            wordWrap: true,
            wordWrapWidth: 200,
            breakWords: true,
        });
    } else {
        sprite = PIXI.Sprite.from(emoji);
        sprite.width = 32;
        sprite.height = 32;
    }
    sprite.anchor.set(0.5, 0.5);

    let x = (parseInt(target_id.substring(6, 6 + 3), 16) - 0x800) / 2 + Math.random() * 30; //次の目標座標
    let y = (parseInt(target_id.substring(12, 12 + 3), 16) - 0x800) / 2 + Math.random() * 30;
    let ox = (parseInt(event.id.substring(6, 6 + 3), 16) - 0x800) / 2; //旧座標
    let oy = (parseInt(event.id.substring(12, 12 + 3), 16) - 0x800) / 2;

    //tx ターゲットx (次の表示位置)
    //x 現在位置x (表示位置)
    others_reaction.push({ tx: x, ty: y, x: ox, y: oy, text_sp: sprite, created_at: event.created_at, text: content, target_pubkey: target_pubkey });
    if (others_reaction.length > 1024) {
        var first = others_reaction.shift();
        others_reaction.text_sp.destroy();
    }

    app.stage.addChild(sprite);

    // 表示に反映
    internal_status.others_reaction = Object.keys(others_reaction).length;
}

function getContactList(pubkey) {
    return new Promise((resolve, reject) => {
        var timeout = setTimeout(resolve, 3000);
        // リレーに取得を依頼する
        let psub = relay.sub([
            {
                kinds: [3],
                limit: 1,
                authors: [pubkey]
            }
        ]);
        psub.on('event', event => {
            if (event.kind === 3) {
                // コンタクトリストイベント
                psub.unsub();

                for (var t in event["tags"]) {
                    if (event["tags"][t][0] == "p") {
                        contacts.push(event["tags"][t][1]);
                    }
                }

                resolve();
                clearTimeout(timeout);
            }
        });
        psub.on('eose', () => {
            psub.unsub();
            resolve();
            clearTimeout(timeout);
        });
    });
}


async function connectRelay(relay_adr) {
    if (window.nostr == undefined) {
        setStatus("⚠ NIP-07 not found!");
        return;
    }
    mypubkey = await window.nostr.getPublicKey();

    // リレーの情報を確認する
    try {
        const nip11 = await (await fetch(relay_adr.replace("wss://", "https://"), { headers: { "Accept": "application/nostr+json" } })).json();
        console.log(nip11);
        if (!nip11["supported_nips"].includes(16)) {
            setStatus("⚠ This relay does not supported NIP-16!");
            return;
        }
        if (!nip11["supported_nips"].includes(33)) {
            setStatus("⚠ This relay does not supported NIP-33!");
            return;
        }
    } catch (e) {
        setStatus("⚠ " + e);
        return;
    }

    await new Promise(async (resolve, reject) => {
        // リレーに接続する
        relay = window.NostrTools.relayInit(relay_adr);
        relay.on('connect', async () => {
            setStatus(`connected to ${relay.url}`)

            // 自己Profileを取得
            await getProfile(mypubkey);
            await getContactList(mypubkey);
            resolve();
        });
        relay.on('error', () => {
            setStatus(`failed to connect to ${relay.url}`)
        });

        await relay.connect();
    });
    // リレーから必要な情報を購読する
    let sub = relay.sub([
        {
            kinds: [1],
            since: Math.round(Date.now() / 1000) - 3600 // 1時間前まで取得
        }
    ]);
    sub.on('event', async event => {
        events.push(event);
    });

    let sub2 = relay.sub([
        {
            kinds: [0, 29420, 30078],
            since: Math.round(Date.now() / 1000) - 3600 // 1時間前まで取得
        }
    ]);
    sub2.on('event', async event => {
        events.push(event);
    });

    // リレーから必要な情報を購読する
    let sub3 = relay.sub([
        {
            kinds: [7],
            since: Math.round(Date.now() / 1000) - 3600 // 1時間前まで取得
        }
    ]);
    sub3.on('event', async event => {
        events.push(event);
    });

    setTimeout(pump, 32);
    addLog("[初回取得処理中...]");
    return mypubkey;
}

async function pump() {
    while (events.length > 0) {
        const event = events.shift();
        console.log(event);
        if (follow_only && contacts.indexOf(event.pubkey) == -1) {
            //フォロー以外弾く
            console.log("IGNORE");
            continue;
        }

        if (user_profiles[event.pubkey] == undefined) {
            await getProfile(event.pubkey);
        }

        if (event.kind === 30078) {
            // 永続的位置情報イベント
            onPositionPermanent(event);
        }

        if (event.kind === 29420) {
            // 位置情報イベント
            onPosition(event);
        }

        if (event.kind === 7) {
            // リアクションイベント
            onReaction(event);
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
    }
    setTimeout(pump, 32);
}