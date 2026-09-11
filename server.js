const express = require("express");
const http = require("http");
const https = require("https");
const { Server } = require("socket.io");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const { Pool } = require("pg");
const pgSession = require("connect-pg-simple")(session);

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const MEDIA_DIR = path.join(__dirname, "public", "media");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "local-dev-only-secret";


// ======================================================
// TEST ALERT ANTI-SPAM
// ======================================================

const TEST_ALERT_COOLDOWN_MS = 5000;

const testAlertCooldown = new Map();


// ======================================================
// DATABASE CHECK
// ======================================================

if (!process.env.DATABASE_URL) {

  console.error(
    "DATABASE_URL is missing"
  );

  process.exit(1);
}


// ======================================================
// MAKE SURE MEDIA FOLDER EXISTS
// ======================================================

if (!fs.existsSync(MEDIA_DIR)) {

  fs.mkdirSync(
    MEDIA_DIR,
    {
      recursive: true
    }
  );
}


// ======================================================
// POSTGRESQL
// ======================================================

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
// STATIC WEBSITE FILES
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
// DATABASE SETUP
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

      payment_mode
      VARCHAR(20)
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
// CREATOR LOGIN PROTECTION
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

  catch (e) {

    console.error(e);


    res
      .status(500)
      .json({

        error:
          "Server error"

      });

  }

}


// ======================================================
// FILE UPLOAD
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

        Date.now() +
        "-" +
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
// VIEWER PAGE
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

    catch (e) {

      console.error(e);


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

        password.length <
          6 ||

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

    catch (e) {

      try {

        await client.query(
          "ROLLBACK"
        );

      }

      catch {}


      console.error(e);


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


      const r =
        await pool.query(

          "SELECT * FROM users WHERE email=$1",

          [email]

        );


      const u =
        r.rows[0];


      if (

        !u ||

        !(
          await bcrypt.compare(

            String(
              req.body.password ||
              ""
            ),

            u.password_hash

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
        u.id;


      const c =
        await creatorById(
          u.creator_id
        );


      res.json({

        ok:
          true,

        slug:
          c?.slug

      });

    }

    catch (e) {

      console.error(e);


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

      () =>
        res.json({
          ok: true
        })

    );

  }

);


// ======================================================
// CURRENT LOGGED IN USER
// ======================================================

app.get(

  "/api/auth/me",

  async (
    req,
    res
  ) => {

    try {

      const u =
        await currentUser(req);


      if (!u) {

        return res
          .status(401)
          .json({

            error:
              "Not logged in"

          });

      }


      const c =
        await creatorById(
          u.creator_id
        );


      res.json({

        email:
          u.email,

        creator:

          c

            ? {

                slug:
                  c.slug,

                displayName:
                  c.display_name

              }

            : null

      });

    }

    catch (e) {

      console.error(e);


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
// PUBLIC CREATOR DATA
// ======================================================

app.get(

  "/api/creator/:slug",

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
          .json({

            error:
              "Creator not found"

          });

      }


      res.json(
        publicCreator(c)
      );

    }

    catch (e) {

      console.error(e);


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

      const c =
        req.creator;


      const tx =
        await pool.query(

          `
          SELECT *
          FROM transactions
          WHERE creator_id=$1
          ORDER BY created_at DESC
          `,

          [c.id]

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
            a,
            b
          ) =>

            a +
            Number(
              b.amount ||
              0
            ),

          0

        );


      const platformFee =
        paid.reduce(

          (
            a,
            b
          ) =>

            a +
            Number(
              b.platform_fee ||
              0
            ),

          0

        );


      const creatorNet =
        paid.reduce(

          (
            a,
            b
          ) =>

            a +
            Number(
              b.creator_net ||
              0
            ),

          0

        );


      const transactions =
        rows.map(

          x => ({

            id:
              x.id,

            viewer:
              x.viewer,

            message:
              x.message,

            amount:
              Number(
                x.amount
              ),

            platformFee:
              Number(
                x.platform_fee
              ),

            creatorNet:
              Number(
                x.creator_net
              ),

            status:
              x.status,

            createdAt:
              x.created_at

          })

        );


      res.json({

        id:
          c.id,

        slug:
          c.slug,

        displayName:
          c.display_name,

        currency:
          c.currency,

        platformFeePercent:
          Number(
            c.platform_fee_percent
          ),

        paymentMode:
          c.payment_mode,

        payout:
          c.payout,

        messageTiers:
          c.message_tiers ||
          [],

        sounds:
          c.sounds ||
          [],

        memes:
          c.memes ||
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
              c.sounds ||
              []
            )

              .filter(

                x =>
                  x.enabled

              )

              .length

        },


        transactions

      });

    }

    catch (e) {

      console.error(e);


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
// FREE SERVER-SIDE TTS
// ======================================================

function proxyTtsRequest(
  targetUrl,
  res,
  redirectsLeft = 2
) {

  const request =
    https.get(

      targetUrl,

      {

        headers: {

          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",

          "Accept":
            "audio/mpeg,audio/*;q=0.9,*/*;q=0.8",

          "Accept-Language":
            "en-IN,en;q=0.9",

          "Referer":
            "https://translate.google.com/"

        },

        timeout:
          10000

      },

      upstream => {

        const status =
          upstream.statusCode ||
          500;


        if (

          status >= 300 &&

          status < 400 &&

          upstream.headers.location &&

          redirectsLeft > 0

        ) {

          upstream.resume();


          return proxyTtsRequest(

            new URL(
              upstream.headers.location,
              targetUrl
            ).toString(),

            res,

            redirectsLeft - 1

          );

        }


        if (
          status !== 200
        ) {

          upstream.resume();


          if (
            !res.headersSent
          ) {

            res
              .status(502)
              .send(
                "TTS provider failed"
              );

          }


          return;

        }


        res.setHeader(

          "Content-Type",

          upstream.headers[
            "content-type"
          ]

          ||

          "audio/mpeg"

        );


        res.setHeader(

          "Cache-Control",

          "no-store, max-age=0"

        );


        res.setHeader(

          "Pragma",

          "no-cache"

        );


        upstream.pipe(
          res
        );

      }

    );


  request.on(

    "timeout",

    () => {

      request.destroy(

        new Error(
          "TTS request timeout"
        )

      );

    }

  );


  request.on(

    "error",

    error => {

      console.error(

        "TTS proxy error:",

        error.message

      );


      if (
        !res.headersSent
      ) {

        res
          .status(502)
          .send(
            "TTS failed"
          );

      }

      else {

        res.end();

      }

    }

  );

}



app.get(

  "/api/tts",

  (
    req,
    res
  ) => {

    const text =

      String(
        req.query.text ||
        ""
      )

        .replace(
          /\s+/g,
          " "
        )

        .trim()

        .slice(
          0,
          180
        );


    if (!text) {

      return res
        .status(400)
        .send(
          "Missing text"
        );

    }


    const ttsUrl =

      "https://translate.google.com/translate_tts"

      +

      "?ie=UTF-8"

      +

      "&client=tw-ob"

      +

      "&tl=en-IN"

      +

      "&q="

      +

      encodeURIComponent(
        text
      );


    proxyTtsRequest(

      ttsUrl,

      res

    );

  }

);


// ======================================================
// TEST PAYMENT + 5 SECOND ANTI-SPAM
// ======================================================

app.post(

  "/api/test-payment/:slug",

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
          .json({

            error:
              "Creator not found"

          });

      }


      // ===============================================
      // ANTI-SPAM
      // ===============================================

      const spamKey =

        `${c.slug}:${req.ip}`;


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
      // PAYMENT DATA
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

          c.platform_fee_percent ||
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
        c.sounds ||
        [];


      const memes =
        c.memes ||
        [];


      const sound =
        sounds.find(

          x =>

            x.id ===
            String(
              body.soundId ||
              ""
            )

            &&

            x.enabled

        );


      const meme =
        memes.find(

          x =>

            x.id ===
            String(
              body.memeId ||
              ""
            )

            &&

            x.enabled

        );


      const safe = {

        creatorSlug:
          c.slug,


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
          ""

      };


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

          c.id,

          safe.name,

          safe.message,

          gross,

          platformFee,

          creatorNet

        ]

      );


      // ===============================================
      // SEND ALERT TO OBS
      // ===============================================

      io
        .to(
          "creator:" +
          c.slug
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

    catch (e) {

      console.error(e);


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

    catch (e) {

      console.error(e);


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

          x =>
            x.id ===
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

    catch (e) {

      console.error(e);


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

            x =>
              x.id !==
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

    catch (e) {

      console.error(e);


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


      const ext =

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
          ext
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
          ext
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

    catch (e) {

      console.error(e);


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
// START SERVER
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

    err => {


      console.error(

        "Database startup failed:",

        err

      );


      process.exit(1);

    }

  );
