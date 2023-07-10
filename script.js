"use strict";

// python -m http.server
// http://localhost:8000/

let app = new PIXI.Application({ width: 800, height: 800 });
let state_x = 0;
let state_y = 0;

function setStatus(s) {
    document.getElementById('status').innerText = s;
}
function setMyPosView(x, y, state_x, state_y) {
    document.getElementById('pos').innerText = "(" + x + "," + y + ") [" + state_x + "," + state_y + "]";
}
function addLog(s) {
    document.getElementById('log').innerText = new Date() + " : " + s + '\n' + document.getElementById('log').innerText.substr(0, 4096);
}

// -------------------------------------------------------------------

/*
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
*/

/*
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
*/


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
document.addEventListener('touchstart', (e) => {
    if (e.touches[0].pageY < window.innerHeight / 3) {
        state_y = -1;
    }
    if (e.touches[0].pageY > window.innerHeight * 2 / 3) {
        state_y = 1;
    }
    if (e.touches[0].pageX < window.innerWidth / 3) {
        state_x = -1;
    }
    if (e.touches[0].pageX > window.innerWidth * 2 / 3) {
        state_x = 1;
    }
});
document.addEventListener('touchend', (e) => {
    state_y = 0;
    state_x = 0;
});

window.addEventListener('load', async (e) => {
    document.getElementById('screen').appendChild(app.view);
    app.resize(window.innerWidth, window.innerHeight);
    let sprite = new PIXI.Text('[YOU]', {
        fontFamily: 'Arial',
        fontSize: 12,
        fill: 0xFFFFFF,
        align: 'center',
    });
    sprite.x = 400;
    sprite.y = 400;
    sprite.anchor.set(0.5);
    app.stage.addChild(sprite);

    let old_state_x = 0;
    let old_state_y = 0;
    app.ticker.add((delta) => {
        if (state_x !== old_state_x || state_y !== old_state_y) {
            old_state_x = state_x;
            old_state_y = state_y;

            setMyPosView(sprite.x, sprite.y, state_x, state_y);
        }

        sprite.y += state_y;
        sprite.x += state_x;
        /*
                for(const c in users){
                    let user = users[c];
                    user.sprite.x = user.content.x;
                    user.sprite.y = user.content.y;
        
                    // ステートに基づく予測座標更新
                    user.content.x += user.content.sx;
                    user.content.y += user.content.sy;
                }
        */
    });
    // --------------------------------------------------------------------
    connectRelay();

    document.getElementById("send_button").addEventListener('click', async (e) => {
        await sendText();
    });
    document.getElementById("message").addEventListener('keyup', async (e) => {
        if(e.key === 'Enter' && e.ctrlKey){
            await sendText();
        }
    });
});

async function sendText()
{
    let element = document.getElementById("message");
    if(element.value.length === 0){return;}

    await postMemo(element.value);
    element.value = "";
}