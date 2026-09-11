const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const { Pool } = require("pg");
const pgSession = require("connect-pg-simple")(session);
const { EdgeTTS } = require("node-edge-tts");

const app = express();
const server = http.createServer(app);
const io = new Server(server);


// ======================================================
// FOLDERS
// ======================================================

const MEDIA_DIR = path.join(
  __dirname,
  "public",
  "media"
);

const TTS_DIR = path.join(
  __dirname,
  "public",
  "tts"
);


fs.mkdirSync(
  MEDIA_DIR,
  { recursive: true }
);

fs.mkdirSync(
  TTS_DIR,
  { recursive: true }
);


// ======================================================
// SETTINGS
// ======================================================

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "local-dev-only-secret";


const TEST_ALERT_COOLDOWN_MS =
  3000;


const testAlertCooldown =
  new Map();


// ======================================================
// DATABASE
// ======================================================

if (!process.env.DATABASE_URL) {

  console.error(
    "DATABASE_URL is missing"
  );

  process.exit(1);
}


const pool = new Pool({

  connectionString:
    process.env.DATABASE_URL

});


// ======================================================
// EXPRESS
// ======================================================

app.set(
  "trust proxy",
  1
);


app.use(
  express.json({
    limit: "1mb"
  })
);


app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb"
  })
);


// ======================================================
// SESSION
// ======================================================

app.use(

  session({

    store: new pgSession({

      pool,

      tableName:
        "user_sessions",

      createTableIfMissing:
        true

    }),

    secret:
      SESSION_SECRET,

    resave:
      false,

    saveUninitialized:
      false,

    cookie: {

      httpOnly:
        true,

      sameSite:
        "lax",

      secure:
        process.env.NODE_ENV ===
        "production",

      maxAge:
        1000 *
        60 *
        60 *
        24 *
        7

    }

  })

);


// ======================================================
// STATIC WEBSITE
// ======================================================

app.use(

  express.static(

    path.join(
      __dirname,
      "public"
    )

  )

);


// ======================================================
// HELPERS
// ======================================================

function cleanName(s) {

  return (

    String(s || "")

      .replace(
        /[^\w .()\-]/g,
        ""
      )

      .slice(
        0,
        80
      )

    ||

    "upload"

  );

}


function slugify(s) {

  return String(s || "")

    .toLowerCase()

    .trim()

    .replace(
      /[^a-z0-9]+/g,
      "-"
    )

    .replace(
      /^-|-$/g,
      ""
    )

    .slice(
      0,
      30
    );

}


function publicCreator(c) {

  return {

    id:
      c.id,

    slug:
      c.slug,

    displayName:
      c.display_name,

    currency:
      c.currency,

    messageTiers:
      c.message_tiers || [],

    sounds:
      c.sounds || [],

    memes:
      c.memes || [],

    platformFeePercent:
      Number(
        c.platform_fee_percent ||
        10
      )

  };

}


// ======================================================
// DATABASE INITIALIZATION
// ======================================================

async function initDB() {

  await pool.query(`

    CREATE TABLE IF NOT EXISTS creators (

      id UUID PRIMARY KEY,

      owner_user_id UUID,

      slug VARCHAR(30)
      UNIQUE
      NOT NULL,

      display_name VARCHAR(50)
      NOT NULL,

      currency VARCHAR(10)
      NOT NULL
      DEFAULT 'INR',

      platform_fee_percent
      NUMERIC(5,2)
      NOT NULL
      DEFAULT 10,

      payment_mode VARCHAR(20)
      NOT NULL
      DEFAULT 'test',

      payout JSONB
      NOT NULL
      DEFAULT
      '{"upiId":"","status":"not_configured"}'::jsonb,

      message_tiers JSONB
      NOT NULL
      DEFAULT '[]'::jsonb,

      sounds JSONB
      NOT NULL
      DEFAULT '[]'::jsonb,

      memes JSONB
      NOT NULL
      DEFAULT '[]'::jsonb,

      created_at TIMESTAMPTZ
      NOT NULL
      DEFAULT NOW()

    )

  `);


  await pool.query(`

    CREATE TABLE IF NOT EXISTS users (

      id UUID PRIMARY KEY,

      email VARCHAR(255)
      UNIQUE
      NOT NULL,

      password_hash TEXT
      NOT NULL,

      creator_id UUID
      UNIQUE
      REFERENCES creators(id)
      ON DELETE CASCADE,

      created_at TIMESTAMPTZ
      NOT NULL
      DEFAULT NOW()

    )

  `);


  await pool.query(`

    CREATE TABLE IF NOT EXISTS transactions (

      id UUID PRIMARY KEY,

      creator_id UUID
      NOT NULL
      REFERENCES creators(id)
      ON DELETE CASCADE,

      viewer VARCHAR(30),

      message VARCHAR(200),

      amount NUMERIC(12,2)
      NOT NULL
      DEFAULT 0,

      platform_fee NUMERIC(12,2)
      NOT NULL
      DEFAULT 0,

      creator_net NUMERIC(12,2)
      NOT NULL
      DEFAULT 0,

      status VARCHAR(30)
      NOT NULL,

      created_at TIMESTAMPTZ
      NOT NULL
      DEFAULT NOW()

    )

  `);


  console.log(
    "PostgreSQL tables ready"
  );

}


// ======================================================
// DATABASE HELPERS
// ======================================================

async function creatorBySlug(slug) {

  const r =
    await pool.query(

      "SELECT * FROM creators WHERE slug=$1",

      [slug]

    );


  return (
    r.rows[0] ||
    null
  );

}


async function creatorById(id) {

  const r =
    await pool.query(

      "SELECT * FROM creators WHERE id=$1",

      [id]

    );


  return (
    r.rows[0] ||
    null
  );

}


async function currentUser(req) {

  if (
    !req.session.userId
  ) {

    return null;

  }


  const r =
    await pool.query(

      "SELECT * FROM users WHERE id=$1",

      [
        req.session.userId
      ]

    );


  return (
    r.rows[0] ||
    null
  );

}


// ======================================================
// LOGIN PROTECTION
// ======================================================

async function requireCreator(
  req,
  res,
  next
) {

  try {

    const u =
      await currentUser(req);


    if (!u) {

      return res
        .status(401)
        .json({

          error:
            "Login required"

        });

    }


    const c =
      await creatorById(
        u.creator_id
      );


    if (!c) {

      return res
        .status(403)
        .json({

          error:
            "Creator account missing"

        });

    }


    req.user =
      u;


    req.creator =
      c;


    next();

  }

  catch (error) {

    console.error(
      error
    );


    res
      .status(500)
      .json({

        error:
          "Server error"

      });

  }

}


// ======================================================
// UPLOAD SETTINGS
// ======================================================

const storage =
  multer.diskStorage({

    destination: (
      req,
      file,
      cb
    ) => {

      cb(
        null,
        MEDIA_DIR
      );

    },


    filename: (
      req,
      file,
      cb
    ) => {

      cb(

        null,

        Date.now()

        +

        "-"

        +

        cleanName(
          file.originalname
        )

      );

    }

  });


const upload =
  multer({

    storage,

    limits: {

      fileSize:
        25 *
        1024 *
        1024

    }

  });


// ======================================================
// TTS TEXT
// ======================================================

function buildVoiceText(
  name,
  amount,
  message
) {

  let text =

    String(
      name ||
      "Viewer"
    ).trim()

    ||

    "Viewer";


  if (
    Number(amount) > 0
  ) {

    text +=

      ` sent ${Number(amount)} rupees.`;

  }

  else {

    text +=

      " sent a message.";

  }


  const cleanMessage =

    String(
      message ||
      ""
    ).trim();


  if (
    cleanMessage
  ) {

    text +=

      ` ${cleanMessage}`;

  }


  return text.slice(
    0,
    260
  );

}


// ======================================================
// CREATE REAL TTS MP3
// ======================================================

async function createVoiceFile(
  text
) {

  const filename =

    `tts-${crypto.randomUUID()}.mp3`;


  const fullPath =

    path.join(
      TTS_DIR,
      filename
    );


  const tts =
    new EdgeTTS({

      voice:
        "en-IN-NeerjaNeural",

      lang:
        "en-IN",

      outputFormat:
        "audio-24khz-48kbitrate-mono-mp3",

      rate:
        "+0%",

      volume:
        "+0%",

      timeout:
        5000

    });


  await tts.ttsPromise(

    text,

    fullPath

  );


  // Delete temporary voice file after 10 mins

  const cleanup =
    setTimeout(

      () => {

        fs.unlink(
          fullPath,
          () => {}
        );

      },

      10 *
      60 *
      1000

    );


  if (
    cleanup.unref
  ) {

    cleanup.unref();

  }


  return (

    "/tts/" +
    filename

  );

}


// ======================================================
// HOME
// ======================================================

app.get(

  "/",

  (
    req,
    res
  ) => {

    res.sendFile(

      path.join(
        __dirname,
        "public",
        "home.html"
      )

    );

  }

);


// ======================================================
// CREATOR VIEWER PAGE
// ======================================================

app.get(

  "/creator/:slug",

  async (
    req,
    res
  ) => {

    try {

      const c =
        await creatorBySlug(
          req.params.slug
        );


      if (!c) {

        return res
          .status(404)
          .send(
            "Creator not found"
          );

      }


      res.sendFile(

        path.join(
          __dirname,
          "public",
          "viewer.html"
        )

      );

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .send(
          "Server error"
        );

    }

  }

);


// ======================================================
// SIGNUP
// ======================================================

app.post(

  "/api/auth/signup",

  async (
    req,
    res
  ) => {

    const client =
      await pool.connect();


    try {

      const email =

        String(
          req.body.email ||
          ""
        )

          .trim()

          .toLowerCase();


      const password =

        String(
          req.body.password ||
          ""
        );


      const displayName =

        String(
          req.body.displayName ||
          ""
        )

          .trim()

          .slice(
            0,
            50
          );


      const slug =

        slugify(

          req.body.slug ||

          displayName

        );


      if (

        !email ||

        password.length < 6 ||

        !displayName ||

        !slug

      ) {

        return res
          .status(400)
          .json({

            error:
              "Name, valid email, 6+ char password and username required"

          });

      }


      const emailCheck =

        await client.query(

          "SELECT id FROM users WHERE email=$1",

          [email]

        );


      if (
        emailCheck.rowCount
      ) {

        return res
          .status(409)
          .json({

            error:
              "Email already registered"

          });

      }


      const slugCheck =

        await client.query(

          "SELECT id FROM creators WHERE slug=$1",

          [slug]

        );


      if (
        slugCheck.rowCount
      ) {

        return res
          .status(409)
          .json({

            error:
              "Username already taken"

          });

      }


      const uid =
        crypto.randomUUID();


      const cid =
        crypto.randomUUID();


      const passwordHash =

        await bcrypt.hash(

          password,

          10

        );


      await client.query(
        "BEGIN"
      );


      await client.query(

        `
        INSERT INTO creators
        (
          id,
          owner_user_id,
          slug,
          display_name,
          currency,
          platform_fee_percent,
          payment_mode,
          payout,
          message_tiers,
          sounds,
          memes
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          'INR',
          10,
          'test',
          $5,
          $6,
          $7,
          $8
        )
        `,

        [

          cid,

          uid,

          slug,

          displayName,


          JSON.stringify({

            upiId:
              "",

            status:
              "not_configured"

          }),


          JSON.stringify([

            {
              max: 50,
              price: 20
            },

            {
              max: 100,
              price: 40
            },

            {
              max: 150,
              price: 70
            },

            {
              max: 200,
              price: 100
            }

          ]),


          JSON.stringify([]),

          JSON.stringify([])

        ]

      );


      await client.query(

        `
        INSERT INTO users
        (
          id,
          email,
          password_hash,
          creator_id
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4
        )
        `,

        [

          uid,

          email,

          passwordHash,

          cid

        ]

      );


      await client.query(
        "COMMIT"
      );


      req.session.userId =
        uid;


      res.json({

        ok:
          true,

        slug

      });

    }

    catch (error) {

      try {

        await client.query(
          "ROLLBACK"
        );

      }

      catch {}


      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Signup failed"

        });

    }

    finally {

      client.release();

    }

  }

);


// ======================================================
// LOGIN
// ======================================================

app.post(

  "/api/auth/login",

  async (
    req,
    res
  ) => {

    try {

      const email =

        String(
          req.body.email ||
          ""
        )

          .trim()

          .toLowerCase();


      const result =

        await pool.query(

          "SELECT * FROM users WHERE email=$1",

          [email]

        );


      const user =
        result.rows[0];


      if (

        !user ||

        !(
          await bcrypt.compare(

            String(
              req.body.password ||
              ""
            ),

            user.password_hash

          )
        )

      ) {

        return res
          .status(401)
          .json({

            error:
              "Invalid email or password"

          });

      }


      req.session.userId =
        user.id;


      const creator =
        await creatorById(
          user.creator_id
        );


      res.json({

        ok:
          true,

        slug:
          creator?.slug

      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Login failed"

        });

    }

  }

);


// ======================================================
// LOGOUT
// ======================================================

app.post(

  "/api/auth/logout",

  (
    req,
    res
  ) => {

    req.session.destroy(

      () => {

        res.json({
          ok: true
        });

      }

    );

  }

);


// ======================================================
// LOGIN STATUS
// ======================================================

app.get(

  "/api/auth/me",

  async (
    req,
    res
  ) => {

    try {

      const user =
        await currentUser(
          req
        );


      if (!user) {

        return res
          .status(401)
          .json({

            error:
              "Not logged in"

          });

      }


      const creator =
        await creatorById(
          user.creator_id
        );


      res.json({

        email:
          user.email,


        creator:

          creator

            ? {

                slug:
                  creator.slug,

                displayName:
                  creator.display_name

              }

            : null

      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Server error"

        });

    }

  }

);


// ======================================================
// PUBLIC CREATOR API
// ======================================================

app.get(

  "/api/creator/:slug",

  async (
    req,
    res
  ) => {

    try {

      const creator =
        await creatorBySlug(
          req.params.slug
        );


      if (!creator) {

        return res
          .status(404)
          .json({

            error:
              "Creator not found"

          });

      }


      res.json(

        publicCreator(
          creator
        )

      );

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Server error"

        });

    }

  }

);


// ======================================================
// DASHBOARD
// ======================================================

app.get(

  "/api/dashboard",

  requireCreator,

  async (
    req,
    res
  ) => {

    try {

      const creator =
        req.creator;


      const tx =

        await pool.query(

          `
          SELECT *
          FROM transactions
          WHERE creator_id=$1
          ORDER BY created_at DESC
          `,

          [
            creator.id
          ]

        );


      const rows =
        tx.rows;


      const paid =

        rows.filter(

          x =>

            [
              "paid",
              "test"
            ].includes(
              x.status
            )

        );


      const gross =

        paid.reduce(

          (
            total,
            row
          ) =>

            total +

            Number(
              row.amount ||
              0
            ),

          0

        );


      const platformFee =

        paid.reduce(

          (
            total,
            row
          ) =>

            total +

            Number(
              row.platform_fee ||
              0
            ),

          0

        );


      const creatorNet =

        paid.reduce(

          (
            total,
            row
          ) =>

            total +

            Number(
              row.creator_net ||
              0
            ),

          0

        );


      const transactions =

        rows.map(

          row => ({

            id:
              row.id,

            viewer:
              row.viewer,

            message:
              row.message,

            amount:
              Number(
                row.amount
              ),

            platformFee:
              Number(
                row.platform_fee
              ),

            creatorNet:
              Number(
                row.creator_net
              ),

            status:
              row.status,

            createdAt:
              row.created_at

          })

        );


      res.json({

        id:
          creator.id,

        slug:
          creator.slug,

        displayName:
          creator.display_name,

        currency:
          creator.currency,

        platformFeePercent:
          Number(
            creator.platform_fee_percent
          ),

        paymentMode:
          creator.payment_mode,

        payout:
          creator.payout,

        messageTiers:
          creator.message_tiers ||
          [],

        sounds:
          creator.sounds ||
          [],

        memes:
          creator.memes ||
          [],


        stats: {

          grossIncome:
            gross,

          platformFee,

          creatorNet,

          totalChats:
            rows.length,

          activeSounds:

            (
              creator.sounds ||
              []
            )

              .filter(

                sound =>
                  sound.enabled

              )

              .length

        },


        transactions

      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Dashboard failed"

        });

    }

  }

);


// ======================================================
// TEST PAYMENT + 3 SECOND ANTI-SPAM
// ======================================================

app.post(

  "/api/test-payment/:slug",

  async (
    req,
    res
  ) => {

    try {

      const creator =
        await creatorBySlug(
          req.params.slug
        );


      if (!creator) {

        return res
          .status(404)
          .json({

            error:
              "Creator not found"

          });

      }


      // ===============================================
      // ANTI SPAM
      // ===============================================

      const spamKey =

        `${creator.slug}:${req.ip}`;


      const now =
        Date.now();


      const lastSent =

        testAlertCooldown.get(
          spamKey
        )

        ||

        0;


      const remaining =

        TEST_ALERT_COOLDOWN_MS

        -

        (
          now -
          lastSent
        );


      if (
        remaining > 0
      ) {

        return res
          .status(429)
          .json({

            error:

              `Please wait ${Math.ceil(

                remaining /
                1000

              )} seconds before sending again.`

          });

      }


      testAlertCooldown.set(

        spamKey,

        now

      );


      const cleanupTimer =

        setTimeout(

          () => {

            if (

              testAlertCooldown.get(
                spamKey
              )

              ===

              now

            ) {

              testAlertCooldown.delete(
                spamKey
              );

            }

          },

          TEST_ALERT_COOLDOWN_MS
          +
          1000

        );


      if (
        cleanupTimer.unref
      ) {

        cleanupTimer.unref();

      }


      // ===============================================
      // VIEWER DATA
      // ===============================================

      const body =
        req.body ||
        {};


      const gross =

        Math.max(

          0,

          Number(
            body.amount ||
            0
          )

        );


      const feePct =

        Number(

          creator.platform_fee_percent ||
          10

        );


      const platformFee =

        Math.round(
          gross *
          feePct
        )

        /

        100;


      const creatorNet =

        Math.round(

          (
            gross -
            platformFee
          )

          *

          100

        )

        /

        100;


      const sounds =
        creator.sounds ||
        [];


      const memes =
        creator.memes ||
        [];


      const sound =

        sounds.find(

          item =>

            item.id ===
            String(
              body.soundId ||
              ""
            )

            &&

            item.enabled

        );


      const meme =

        memes.find(

          item =>

            item.id ===
            String(
              body.memeId ||
              ""
            )

            &&

            item.enabled

        );


      const safe = {

        creatorSlug:
          creator.slug,


        name:

          String(
            body.name ||
            "Viewer"
          )

            .trim()

            .slice(
              0,
              30
            ),


        message:

          String(
            body.message ||
            ""
          )

            .trim()

            .slice(
              0,
              200
            ),


        soundId:

          String(
            body.soundId ||
            ""
          ),


        memeId:

          String(
            body.memeId ||
            ""
          ),


        amount:
          gross,


        platformFee,


        creatorNet,


        soundFile:

          sound?.file ||
          "",


        memeFile:

          meme?.file ||
          "",


        voiceFile:
          ""

      };


      // ===============================================
      // CREATE TTS FIRST
      // ===============================================

      const voiceText =

        buildVoiceText(

          safe.name,

          safe.amount,

          safe.message

        );


      try {

        safe.voiceFile =

          await createVoiceFile(
            voiceText
          );

      }

      catch (ttsError) {

        console.error(

          "TTS generation failed:",

          ttsError.message

        );


        /*
          VERY IMPORTANT:

          TTS fail hone par bhi
          sound/meme alert continue hoga.
        */

        safe.voiceFile =
          "";

      }


      // ===============================================
      // SAVE TRANSACTION
      // ===============================================

      await pool.query(

        `
        INSERT INTO transactions
        (
          id,
          creator_id,
          viewer,
          message,
          amount,
          platform_fee,
          creator_net,
          status
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          'test'
        )
        `,

        [

          crypto.randomUUID(),

          creator.id,

          safe.name,

          safe.message,

          gross,

          platformFee,

          creatorNet

        ]

      );


      // ===============================================
      // SEND TO OBS
      // ===============================================

      io
        .to(

          "creator:" +
          creator.slug

        )

        .emit(

          "show-alert",

          safe

        );


      res.json({

        ok:
          true,


        breakdown: {

          gross,

          platformFee,

          creatorNet

        }

      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Payment test failed"

        });

    }

  }

);


// ======================================================
// PAYOUT
// ======================================================

app.post(

  "/api/dashboard/payout",

  requireCreator,

  async (
    req,
    res
  ) => {

    try {

      const payout = {

        upiId:

          String(
            req.body.upiId ||
            ""
          )

            .trim()

            .slice(
              0,
              80
            ),


        status:
          "saved-test"

      };


      await pool.query(

        `
        UPDATE creators
        SET payout=$1
        WHERE id=$2
        `,

        [

          JSON.stringify(
            payout
          ),

          req.creator.id

        ]

      );


      res.json({
        ok: true
      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Save failed"

        });

    }

  }

);


// ======================================================
// UPDATE SOUND / MEME
// ======================================================

app.post(

  "/api/dashboard/item/:type/:id",

  requireCreator,

  async (
    req,
    res
  ) => {

    try {

      const key =

        req.params.type ===
        "sound"

          ? "sounds"

          : "memes";


      const list = [

        ...(
          req.creator[key] ||
          []
        )

      ];


      const item =

        list.find(

          current =>
            current.id ===
            req.params.id

        );


      if (!item) {

        return res
          .status(404)
          .json({

            error:
              "Item not found"

          });

      }


      if (
        req.body.name !==
        undefined
      ) {

        item.name =

          String(
            req.body.name
          )

            .slice(
              0,
              60
            );

      }


      if (
        req.body.price !==
        undefined
      ) {

        item.price =

          Math.max(

            0,

            Number(
              req.body.price ||
              0
            )

          );

      }


      if (
        req.body.enabled !==
        undefined
      ) {

        item.enabled =

          Boolean(
            req.body.enabled
          );

      }


      await pool.query(

        `
        UPDATE creators
        SET ${key}=$1
        WHERE id=$2
        `,

        [

          JSON.stringify(
            list
          ),

          req.creator.id

        ]

      );


      res.json({

        ok:
          true,

        item

      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Update failed"

        });

    }

  }

);


// ======================================================
// DELETE SOUND / MEME
// ======================================================

app.delete(

  "/api/dashboard/item/:type/:id",

  requireCreator,

  async (
    req,
    res
  ) => {

    try {

      const key =

        req.params.type ===
        "sound"

          ? "sounds"

          : "memes";


      const list =

        (
          req.creator[key] ||
          []
        )

          .filter(

            item =>
              item.id !==
              req.params.id

          );


      await pool.query(

        `
        UPDATE creators
        SET ${key}=$1
        WHERE id=$2
        `,

        [

          JSON.stringify(
            list
          ),

          req.creator.id

        ]

      );


      res.json({
        ok: true
      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Delete failed"

        });

    }

  }

);


// ======================================================
// UPLOAD SOUND / MEME
// ======================================================

app.post(

  "/api/dashboard/upload/:type",

  requireCreator,

  upload.single(
    "file"
  ),

  async (
    req,
    res
  ) => {

    try {

      if (!req.file) {

        return res
          .status(400)
          .json({

            error:
              "Missing file"

          });

      }


      const isSound =

        req.params.type ===
        "sound";


      const extension =

        path

          .extname(
            req.file.filename
          )

          .toLowerCase();


      if (

        isSound &&

        ![
          ".mp3",
          ".wav",
          ".m4a"
        ].includes(
          extension
        )

      ) {

        return res
          .status(400)
          .json({

            error:
              "Use MP3/WAV/M4A"

          });

      }


      if (

        !isSound &&

        ![
          ".mp4",
          ".gif",
          ".webm"
        ].includes(
          extension
        )

      ) {

        return res
          .status(400)
          .json({

            error:
              "Use MP4/GIF/WEBM"

          });

      }


      const key =

        isSound

          ? "sounds"

          : "memes";


      const list = [

        ...(
          req.creator[key] ||
          []
        )

      ];


      list.push({

        id:

          (
            isSound
              ? "s"
              : "m"
          )

          +

          Date.now(),


        name:

          String(

            req.body.name

            ||

            path.parse(
              req.file.originalname
            ).name

          )

            .slice(
              0,
              60
            ),


        file:

          "/media/" +
          req.file.filename,


        price:

          Math.max(

            0,

            Number(
              req.body.price ||
              0
            )

          ),


        enabled:
          true

      });


      await pool.query(

        `
        UPDATE creators
        SET ${key}=$1
        WHERE id=$2
        `,

        [

          JSON.stringify(
            list
          ),

          req.creator.id

        ]

      );


      res.json({
        ok: true
      });

    }

    catch (error) {

      console.error(
        error
      );


      res
        .status(500)
        .json({

          error:
            "Upload failed"

        });

    }

  }

);


// ======================================================
// SOCKET.IO
// ======================================================

io.on(

  "connection",

  socket => {


    socket.on(

      "join-creator",

      slug => {


        socket.join(

          "creator:" +

          String(
            slug ||
            ""
          )

        );

      }

    );

  }

);


// ======================================================
// START
// ======================================================

const PORT =

  process.env.PORT ||
  3000;


initDB()

  .then(

    () => {


      server.listen(

        PORT,

        "0.0.0.0",

        () => {


          console.log(

            `CHITCHAT PostgreSQL server running on port ${PORT}`

          );

        }

      );

    }

  )

  .catch(

    error => {


      console.error(

        "Database startup failed:",

        error

      );


      process.exit(1);

    }

  );
