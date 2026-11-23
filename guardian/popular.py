"""Well-known package names used as typosquatting targets.

A heuristic list, not a registry snapshot: a name one edit away from one of
these, that is not itself on the list, is flagged for review (not convicted).
"""

NPM = set("""
react react-dom react-router react-router-dom redux react-redux next vue vue-router vuex nuxt angular
@angular/core @angular/common @angular/router @angular/forms @angular/cli svelte preact jquery lodash
lodash-es underscore ramda moment dayjs date-fns luxon axios node-fetch got request superagent
cross-fetch express koa fastify hapi connect body-parser cookie-parser cors helmet morgan compression
multer passport jsonwebtoken bcrypt bcryptjs argon2 uuid nanoid shortid chalk colors kleur picocolors
debug commander yargs minimist inquirer ora dotenv cross-env rimraf mkdirp glob minimatch fs-extra
graceful-fs chokidar semver async bluebird rxjs eventemitter3 ws socket.io socket.io-client typescript
ts-node tslib @types/node babel-core @babel/core @babel/preset-env @babel/runtime webpack webpack-cli
webpack-dev-server rollup vite esbuild parcel terser uglify-js eslint prettier jest mocha chai sinon
vitest cypress puppeteer playwright karma jasmine nyc istanbul supertest nock mongoose mongodb mysql
mysql2 pg sequelize typeorm prisma knex redis ioredis sqlite3 better-sqlite3 tedious graphql
apollo-server @apollo/client handlebars ejs pug mustache marked markdown-it highlight.js sharp jimp
canvas pdfkit xml2js cheerio jsdom htmlparser2 yaml js-yaml ini toml csv-parse papaparse xlsx
nodemailer twilio stripe aws-sdk @aws-sdk/client-s3 firebase firebase-admin googleapis
@google-cloud/storage winston pino bunyan log4js node-cron cron agenda bull bullmq amqplib kafkajs
validator joi yup zod ajv class-validator qs query-string url-parse whatwg-url path-to-regexp
http-proxy http-proxy-middleware proxy-agent https-proxy-agent socks-proxy-agent form-data busboy
formidable mime mime-types content-type iconv-lite buffer safe-buffer core-js regenerator-runtime
classnames clsx styled-components emotion @emotion/react tailwindcss postcss autoprefixer sass less
node-sass bootstrap material-ui @mui/material antd chart.js d3 three electron nodemon pm2 concurrently
npm-run-all husky lint-staged lerna nx turbo serve http-server live-server open opn execa shelljs
cross-spawn which tar archiver adm-zip jszip unzipper extract-zip node-gyp prebuild-install bindings
nan node-pre-gyp event-stream through2 readable-stream stream-browserify browserify ua-parser-js
coa rc colors.js faker @faker-js/faker crypto-js bignumber.js big.js decimal.js ethers web3 lodash.merge
lodash.get lodash.set deepmerge object-assign extend immer immutable mobx zustand jotai swr
react-query @tanstack/react-query formik react-hook-form i18next react-i18next intl moment-timezone
""".split())

PYPI = set("""
requests urllib3 certifi idna charset-normalizer chardet six setuptools wheel pip packaging pyparsing
numpy pandas scipy matplotlib seaborn scikit-learn sklearn tensorflow torch torchvision keras jax
transformers tokenizers datasets huggingface-hub openai anthropic langchain langchain-core tiktoken
flask django fastapi starlette uvicorn gunicorn werkzeug jinja2 markupsafe itsdangerous click
pydantic attrs dataclasses-json marshmallow sqlalchemy alembic psycopg2 psycopg2-binary pymysql
mysqlclient redis celery kombu boto3 botocore s3transfer awscli google-auth google-api-core
google-cloud-storage protobuf grpcio pyyaml toml tomli python-dateutil pytz tzdata arrow pendulum
cryptography pyopenssl pycryptodome bcrypt paramiko pyjwt oauthlib requests-oauthlib httpx aiohttp
httplib2 websockets beautifulsoup4 lxml html5lib selenium scrapy pillow opencv-python imageio
pytest pytest-cov coverage tox nose mock hypothesis black flake8 pylint mypy isort autopep8 ruff
virtualenv poetry pipenv twine docutils sphinx tqdm rich colorama termcolor tabulate prettytable
psutil pexpect ptyprocess filelock platformdirs appdirs importlib-metadata zipp typing-extensions
wrapt decorator cachetools simplejson ujson orjson msgpack pyzmq greenlet gevent eventlet
python-dotenv environs dnspython netaddr ipaddress pyasn1 rsa jmespath docker kubernetes ansible
fabric invoke networkx sympy statsmodels xgboost lightgbm catboost nltk spacy gensim openpyxl xlrd
xlsxwriter python-docx reportlab pypdf2 pymongo elasticsearch sentry-sdk loguru structlog
""".split())

# Legitimate packages that sit one edit away from a popular name (never flag these).
KNOWN_LEGIT = {
    "npm": set("""gaxios http-proxy-agent through agent-base debug-log colors color chalk-template
                  uuidv4 node-forge nodemon yarn esprima espree execa exec pump pumpify mime-db
                  readdirp anymatch braces inherits once wrappy""".split()),
    "pypi": set("""psycopg psycopg-binary psycopg-pool request-toolbelt requests-toolbelt pyyaml-include
                   docker-compose attr attrs six sixer tomli-w tomlkit""".split()),
}

POPULAR = {"npm": NPM, "pypi": PYPI}
