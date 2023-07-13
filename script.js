"use strict";

// python -m http.server
// http://localhost:8000/

// キャンバス
let app = new PIXI.Application({ width: 800, height: 800 });
let bg_sprite;

// フォロー限定
let follow_only = false;

// 自キャラクター状態
let player = {
    x: 0,
    y: 0,
    z: 0,
    speed_x: 0,
    speed_y: 0,
    moved: false,
    created_at: 0
}

// 自分のスプライト
let player_icon_sprite;
let player_text_sprite;
let player_text = "☆";

// 他のスプライト
let others = {};
let others_text = [];
let others_reaction = [];
let internal_status = {};

// ステータス表示を画面に反映
function setStatus(s) {
    document.getElementById('status').innerText = s;
}

// ステータス表示を画面に反映
function setStatusInternal() {
    document.getElementById('status_internal').innerText = JSON.stringify(internal_status);
}

// ステータス表示を画面に反映
function setPlayerState() {
    document.getElementById('pos').innerText = JSON.stringify(player);
}

// ログを追加
function addLog(s) {
    console.log(s);

    const el = document.getElementById('log');
    el.innerText = new Date() + " : " + s + '\n' + el.innerText.substring(0, 4096);
}

// -------------------------------------------------------------------

// キー押されたとき
document.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp') {
        player.speed_y = -1;
    }
    if (e.key === 'ArrowDown') {
        player.speed_y = 1;
    }
    if (e.key === 'ArrowLeft') {
        player.speed_x = -1;
    }
    if (e.key === 'ArrowRight') {
        player.speed_x = 1;
    }
});

// キー離されたとき
document.addEventListener('keyup', (e) => {
    if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        player.speed_y = 0;
        player.moved = true;
    }
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        player.speed_x = 0;
        player.moved = true;
    }
});

// タッチされたとき
document.addEventListener('touchstart', (e) => {
    if (e.touches[0].pageY < window.innerHeight / 3) {
        player.speed_y = -1;
    }
    if (e.touches[0].pageY > window.innerHeight * 2 / 3) {
        player.speed_y = 1;
    }
    if (e.touches[0].pageX < window.innerWidth / 3) {
        player.speed_x = -1;
    }
    if (e.touches[0].pageX > window.innerWidth * 2 / 3) {
        player.speed_x = 1;
    }
});

// タッチ離されたとき
document.addEventListener('touchend', (e) => {
    player.speed_x = 0;
    player.speed_y = 0;
    player.moved = true;
});

// 画面読み込み時
window.addEventListener('load', async (e) => {
    // 送信エリアでCtrl + Enter
    document.getElementById("message").addEventListener('keyup', async (e) => {
        if (e.key === 'Enter' && e.ctrlKey) {
            await sendText();
            postPositionPermanent(player.x, player.y, player.z);
        }
    });

    // 送信ボタン
    document.getElementById("send_button").addEventListener('click', async (e) => {
        await sendText();
        postPositionPermanent(player.x, player.y, player.z);
    });

    // 変化があれば10秒おきに実行
    setInterval(() => {
        if (player.moved) {
            player.moved = false;
            postPosition(player.x, player.y, player.z);
            console.log("Player Position Update!(10sec)");
        }
    }, 10 * 1000);

    // 変化がなくても60秒おきに実行
    setInterval(() => {
        player.moved = false;
        postPosition(player.x, player.y, player.z);
        console.log("Player Position Update!(60sec)");
    }, 60 * 1000);

    // リレー接続ボタン(初期化処理開始)
    document.getElementById("relay_connect_button").addEventListener('click', async (e) => {
        // 画面切り替え
        document.getElementById('connect_relay').style = 'display:none';
        document.getElementById('play_screen').style = 'display:block';

        follow_only = document.getElementById("follow only").checked;

        // リレーへの接続を開始
        const relay_adr = document.getElementById("relay_address").value;
        const mypubkey = await connectRelay(relay_adr);

        // 初期位置を送信
        player.x = ((Math.random() - 0.5) * 100);
        player.y = ((Math.random() - 0.5) * 100);
        postPosition(player.x, player.y, player.z);

        // キャンバスの初期化を実施
        document.getElementById('screen').appendChild(app.view);

        // 背景画像
        bg_sprite = PIXI.Sprite.from("bg.png");
        bg_sprite.roundPixels = false;
        bg_sprite.width = 8000;
        bg_sprite.height = 8000;
        bg_sprite.anchor.set(0.5, 0.5);
        app.stage.addChild(bg_sprite);

        // テキスト
        player_text_sprite = new PIXI.Text("☆", {
            fontFamily: 'Arial',
            fontSize: 12,
            fill: upRGB(mypubkey),
            align: 'center',
            wordWrap: true,
            wordWrapWidth: 200,
            breakWords: true,
        });
        player_text_sprite.x = 400;
        player_text_sprite.y = 400;
        player_text_sprite.anchor.set(0.5, 0);
        app.stage.addChild(player_text_sprite);

        // 自スプライトを作成(位置固定)
        let picture = "unknown.png"
        if (user_profiles[mypubkey].picture != "") {
            picture = user_profiles[mypubkey].picture;
        }

        player_icon_sprite = PIXI.Sprite.from(picture);
        player_icon_sprite.x = 400;
        player_icon_sprite.y = 400;
        player_icon_sprite.width = 64;
        player_icon_sprite.height = 64;
        player_icon_sprite.anchor.set(0.5, 1.0);
        app.stage.addChild(player_icon_sprite);

        // 描画ループ
        app.ticker.add((delta) => {
            setPlayerState();
            setStatusInternal();

            // 自己状態を更新
            player.x += (player.speed_x * delta);
            player.y += (player.speed_y * delta);

            player_text_sprite.alpha = 1.0;//(30.0 - (Math.floor(Date.now() / 1000) - player.created_at)) / 30.0; //30秒で消える

            var player_len = ((Date.now() / 1000.0) - player.created_at) * player_text.length; //1秒でタイプされる
            if (player_len < player_text.length) {
                player_text_sprite.text = player_text.substring(0, Math.floor(player_len));
            } else {
                player_text_sprite.text = player_text;
            }

            bg_sprite.x = - player.x + 400;
            bg_sprite.y = - player.y + 400;

            // 他スプライトを更新
            for (const o in others) {
                let other = others[o];

                if (other.icon_sp.texture == null) {
                    other.icon_sp = PIXI.Sprite.from("unknown.png");
                }

                // 相対位置を反映
                other.text_sp.x = other.x - player.x + 400;
                other.text_sp.y = other.y - player.y + 400;
                other.icon_sp.x = other.x - player.x + 400;
                other.icon_sp.y = other.y - player.y + 400;

                // 透明度計算
                let a = (3600.0 - (Math.floor(Date.now() / 1000) - other.created_at)) / 3600.0; //1時間で消える
                other.icon_sp.alpha = a;
                other.text_sp.alpha = a;

                // 移動
                other.x = other.tx * 0.01 + other.x * 0.99;
                other.y = other.ty * 0.01 + other.y * 0.99;

                // kind 29420情報がある場合 & 3分以内のとき
                if (user_positions[o] != undefined && (Math.floor(Date.now() / 1000) - user_positions[o].created_at) < 600 ) { //10分で時間切れ
                    // 位置情報をオーバーライド
                    other.tx = user_positions[o].x;
                    other.ty = user_positions[o].y;
                    // 位置情報が有効ならサイズを大きくする
                    other.icon_sp.width = 64;
                    other.icon_sp.height = 64;

                    a = 1.0;//(30.0 - (Math.floor(Date.now() / 1000) - other.created_at)) / 30.0; //30秒で消える
                    other.icon_sp.alpha = 1.0;
                    other.text_sp.alpha = a;
                }

                // タイピング効果
                var namelen = 0.0;
                if (other.name != undefined) {
                    namelen = 0.0 + other.name.length;
                }
                var len = namelen + ((Date.now() / 1000.0) - other.created_at) / 3.0 * other.text.length; //3秒でタイプされる
                if (len < other.text.length) {
                    other.text_sp.text = other.text.substring(0, Math.floor(len));
                } else {
                    other.text_sp.text = other.text;
                }
            }

            // 他テキストスプライトを更新
            for (const o in others_text) {
                let other = others_text[o];

                // 相対位置を反映
                other.text_sp.x = other.x - player.x + 400;
                other.text_sp.y = other.y - player.y + 400;

                // 透明度計算
                let a = (3600.0 - (Math.floor(Date.now() / 1000) - other.created_at)) / 3600.0; //1時間で消える
                other.text_sp.alpha = a;
            }

            // 他リアクションスプライトを更新
            for (const o in others_reaction) {
                let other = others_reaction[o];

                // 相対位置を反映
                other.text_sp.x = other.x - player.x + 400;
                other.text_sp.y = other.y - player.y + 400;

                // 透明度計算
                let a = (3600.0 - (Math.floor(Date.now() / 1000) - other.created_at)) / 3600.0; //1時間で消える
                other.text_sp.alpha = a;

                // 移動
                other.x = other.tx * 0.01 + other.x * 0.99;
                other.y = other.ty * 0.01 + other.y * 0.99;

                // kind 29420情報がある場合
                if (user_positions[other.target_pubkey] != undefined) {
                    // 位置情報をオーバーライド
                    other.tx = user_positions[other.target_pubkey].x;
                    other.ty = user_positions[other.target_pubkey].y;

                    a = (30.0 - (Math.floor(Date.now() / 1000) - other.created_at)) / 30.0; //30秒で消える
                    other.text_sp.alpha = a;
                }
            }


            /*
            if(others.length > 3){
                // バッファから削除
                const child = others.shift();
                // 表示から除去
                app.stage.removeChild(child.text_sp);
                app.stage.removeChild(child.icon_sp);
            }
            */
        });
    });
});


async function sendText() {
    let element = document.getElementById("message");
    if (element.value.length === 0) { return; }

    await postMemo(element.value);
    element.value = "";
}