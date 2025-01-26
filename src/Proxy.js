const zlib = require('zlib')
const parse = require('url-parse')
const queryString = require('query-string')
const cookiejar = require('cookiejar')
const iconv = require('iconv-lite')
//const logger = require('./logger')
const { createProxyMiddleware } = require('http-proxy-middleware')
const httpProxy = require('http-proxy')

var proxy = httpProxy.createProxyServer({});

var contentTypeIsText = (headers) => {
  return (!headers["content-type"] || headers["content-type"].indexOf('text/') !== -1 || headers["content-type"].indexOf('javascript') !== -1 || headers["content-type"].indexOf('urlencoded') !== -1 || headers["content-type"].indexOf('json') !== -1) ? true : false;
}

var enableCors = function(req, res) {
  if (req.headers['access-control-request-method']) res.setHeader('access-control-allow-methods', req.headers['access-control-request-method']);
  if (req.headers['access-control-request-headers']) res.setHeader('access-control-allow-headers', req.headers['access-control-request-headers']);
  if (req.headers.origin) {
    res.setHeader('access-control-allow-origin', req.headers.origin);
    res.setHeader('access-control-allow-credentials', 'true');
  }
};

var redirect2HomePage = function({res, httpprefix, serverName,} ) {
  try {
    res.setHeader('location',`${httpprefix}://${serverName}`)
  } catch(e) {
    return
  }
  res.status(302).send(``)
}

let getHostFromReq = ({req, serverName}) => { // return target
  let https_prefix = '/https/'
  let http_prefix = '/http/'
  let host = ''
  let httpType = 'https'
  if (req.url.startsWith(https_prefix)) {
    host = req.url.slice(https_prefix.length, req.url.length)
    let hosts = host.match(/[-a-z0-9A-Z]+\.[-a-z0-9A-Z.]+/g);
    host = hosts.length>0?hosts[0]:''
  } else if (req.url.startsWith(http_prefix)) {
    host = req.url.slice(http_prefix.length, req.url.length)
    let hosts = host.match(/[-a-z0-9A-Z]+\.[-a-z0-9A-Z.]+/g);
    host = hosts.length>0?hosts[0]:''
    httpType = 'http'
  } else if (req.headers['referer'] && req.headers['referer'].indexOf('https/') !== -1) {
      let start = req.headers['referer'].indexOf('https/') + 6
      host = req.headers['referer'].slice(start, req.headers['referer'].length)
      let end = host.indexOf('/')
      if (end === -1) {
        end = host.length
      }
      host = host.slice(0, end)
  } else if (req.headers['referer'] && req.headers['referer'].indexOf('http/') !== -1) {
      let start = req.headers['referer'].indexOf('http/') + 5
      host = req.headers['referer'].slice(start, req.headers['referer'].length)
      let end = host.indexOf('/')
      if (end === -1) {
        end = host.length
      }
      host = host.slice(0, end)
      httpType = 'http'
  } else if (req.headers['referer']) { // 'zh.wikipedia.org'
      var parsed = parse(req.headers['referer'])
      if(parsed.hostname) {
        host = parsed.hostname
        httpType = parsed.protocol.replace(':', '')
      } else {
        host = req.headers['referer']
        httpType = 'https'
      }
  }
  let originalHost = ''
  if (req.headers['cookie']) {
    let cookiesList = req.headers['cookie'].split(' ')
    .map(str => new cookiejar.Cookie(str))
    .map(cookie => {
      if (cookie.name === 'ORIGINALHOST') {
        originalHost = cookie.value
      }
    })
  }
  let localServeList = ['/index.html', '/', '/favicon.png']
  if (host === '' || (host === serverName && !localServeList.includes(req.url))) {
    if (originalHost !== '') {
        httpType = originalHost.split('/')[0]
        host = originalHost.split('/')[1]
    }
  }
  return { host, httpType }
}

let Proxy = ({ httpprefix, serverName, locationReplaceMap302, regReplaceMap, siteSpecificReplace, pathReplace }) => {
    var locationMod302 = ({res, serverName, httpprefix, host, httpType}) => {
        let location = res.getHeaders()['location']
        if (res.statusCode == '301' || res.statusCode == '302' || res.statusCode == '303' ||res.statusCode == '307' || res.statusCode == '308') {
            location = locationReplaceMap302({location, serverName, httpprefix, host, httpType})
            try {
                res.setHeader('location', location)
            } catch(e) {
                return false
            }
        }
        return true
    }
    let handleRespond = ({req, res, body, gbFlag}) => { // text file
        let myRe
        let { host, httpType } = getHostFromReq({req, serverName})
        if (locationMod302({res, serverName, httpprefix, host, httpType}) === false) {
            return
        }
        // logSave(`HandleRespond(), req.url:${req.url}, req.headers:${JSON.stringify(req.headers)}`)
        for(let key in regReplaceMap) {
            myRe = new RegExp(key, 'g') // match group
            body = body.replace(myRe, regReplaceMap[key])
        }
        if (host) {
            body = pathReplace({host, httpType, body})   //13ms
        }
        myRe = new RegExp(`/${httpType}/${host}/${httpType}/${host}/`, 'g') // match group
        body = body.replace(myRe, `/${httpType}/${host}/`)
        // put siteSpecificReplace at end
        Object.keys(siteSpecificReplace).forEach( (site) => {
            if (!req.url) {
                return
            }
            if (req.url.indexOf(site) !== -1 || (req.headers['referer'] && req.headers['referer'].indexOf(site) !== -1)) {
                let keys = Object.keys(siteSpecificReplace[site])
                keys.forEach( key => {
                    myRe = new RegExp(key, 'g') // match group
                    body = body.replace(myRe, siteSpecificReplace[site][key])
                })
            }
        }) //17ms

        if (gbFlag) {
          body = iconv.encode(body, 'gbk')
        }
        // googlevideo.com manual redirection
        if (typeof(body) === 'string' && body.startsWith(`${httpprefix}://${serverName}`) && body.indexOf('googlevideo.com') !== -1) {
            // need to manually redirect it for youtube workaround.
            //logger.info(`============== redirect googlevideo.com`)
            try {
                res.setHeader('location', body) //0ms
            } catch(e) {
                //logger.error(`error: ${e}`)
                return
            }
            res.statusCode = '302'
        }
        // logSave(`5 after replacment,displayed string: ${body}`)
        body = zlib.gzipSync(body) //body is Buffer
        try {
            res.setHeader('content-encoding', 'gzip');
            if (req.headers['debugflag']==='true') {
                res.removeHeader('content-encoding')
                res.setHeader('content-type','text/plain')
                body = `handleRespond: res.statusCode:${res.statusCode}, res.headers:${JSON.stringify(res.getHeaders())}`
            }
            res.end(body);
        } catch(e) {
        }
    }
    // only support https for now.
    const router = req => {
      //return target
      let myRe = new RegExp(`/http[s]?/${serverName}.*?/`, "g"); // match group
      req.url = req.url.replace(myRe, "/");

      let { host, httpType } = getHostFromReq({ req, serverName });
      let target = `${httpType}://${host}`;
      return target;
    };

    let pc = async (req, res, next) => {
      try {
        const activeProxyOptions = await this.prepareProxyRequest(req);
        proxy.web(req, res, activeProxyOptions);
      } catch (err) {
        next(err);
      }
    }
    let p = createProxyMiddleware({
      target: `https://www.google.com`,
      router,
      protocolRewrite: true,
      cookieDomainRewrite: serverName,
      secure: false,
      changeOrigin: true,
      onError: (err, req, res) => {
        //logger.error(`onerror: ${JSON.stringify(err)}`)
        try {
            if ((err.code && (err.code === 'ECONNREFUSED'|| err.code === 'EHOSTUNREACH'|| err.code === 'EPROTO'||
                              err.code === 'ECONNRESET'|| err.code === 'ENOTFOUND')) ||
                (err.reason && err.reason.indexOf('Expected') === -1)) {
                redirect2HomePage({res, httpprefix, serverName,})
            }
        } catch(e) {
            //logger.error(`error of sending 404: ${e}`)
        }
      },
      selfHandleResponse: true, // so that the onProxyRes takes care of sending the response
      onProxyRes: (proxyRes, req, res) => {
        let { host, httpType } = getHostFromReq({req, serverName})
        let bodyList = []
        let bodyLength = 0
        let endFlag = false
        proxyRes.on('data', function(data) {
            if (endFlag === true) {
              return // don't have to push it to bodyList
            }
            bodyLength += data.length // data is Uint8Array for cloueflare, and Buffer for node environment
            bodyList.push(data)
            if (bodyLength >= 2500000 && contentTypeIsText(proxyRes.headers) !== true) {
                let body = Buffer.concat(bodyList) // body is Buffer for node environment
                let fwdStr = req.headers['X-Forwarded-For'] || req.headers['x-forwarded-for']
                let contentType = proxyRes.headers['content-type']
                let contentLen = proxyRes.headers['content-length']
                if (contentLen >= 155000000 ||
                    (host.indexOf('googlevideo') !== -1 && contentLen >= 2500000)) {
                }
                bodyList = []
                bodyLength = 0
                res.write(body)
            }
        })
        proxyRes.on('end', function() {
          if (endFlag === true) {
            return
          }
          let body = Buffer.concat(bodyList) // body is Buffer
          let gbFlag = false
          if (proxyRes.headers["content-encoding"] === 'gzip' || proxyRes.headers["content-encoding"] === 'br') { // gzip/br encoding
            let gunzipped
            try {
              if (proxyRes.headers["content-encoding"] === "br") {
                gunzipped = zlib.brotliDecompressSync(body);
              } else {
                gunzipped = zlib.gunzipSync(body);
              }
            } catch(e) {
                //logger.error(`error2:${e}`)
                return
            }
            if (contentTypeIsText(proxyRes.headers) === true) { //gzip and text
                if (!gunzipped) {
                    redirect2HomePage({res, httpprefix, serverName,})
                    return
                }
                let originBody = gunzipped
                body = gunzipped.toString('utf-8')
                let searchBody = body.slice(0, 1000)
                if (searchBody.indexOf('="text/html; charset=gb') !== -1 ||
                    searchBody.search(/ontent=.*charset="gb/) !== -1 ||
                    searchBody.search(/ONTENT=.*charset="gb/) !== -1 ||
                    searchBody.indexOf('=\'text/html; charset=gb') !== -1) {
                    body = iconv.decode(originBody, 'gbk')
                    gbFlag = true
                }
                let fwdStr = req.headers['X-Forwarded-For'] || req.headers['x-forwarded-for'] || ''
                if (proxyRes.statusCode === 200 && proxyRes.headers["content-type"] &&
                    proxyRes.headers["content-type"].indexOf('text/html') !== -1) {
                }
                if (proxyRes.statusCode === 200 && req.url.indexOf('/sw.js') !== -1) {
                    // fetching sw.js
                    res.setHeader('service-worker-allowed','/')
                }
                handleRespond({req, res, body, gbFlag}) // body is a displayed string
            } else { // gzip and non-text
                let fwdStr = req.headers['X-Forwarded-For'] || req.headers['x-forwarded-for']
                let contentType = proxyRes.headers['content-type']
                let contentLen = proxyRes.headers['content-length']
                try {
                    res.end(body)
                } catch(e) {
                    //logger.info(`error:${e}`)
                }
            }
          } else if (proxyRes.statusCode === 301 || proxyRes.statusCode === 302 || proxyRes.statusCode === 307 || proxyRes.statusCode === 308 ||
                     contentTypeIsText(proxyRes.headers) === true) { // text with non gzip encoding
            let originBody = body
            if (process.env.cloudflare === 'true') { // in cloudflare environment
                body = new TextDecoder().decode(body) // Uint8Array(utf-8 arrayBuffer) toString('utf-8')
            } else { // node environment
                body = body.toString('utf-8');
            }
            if (body.indexOf('="text/html; charset=gb') !== -1 ||
                body.indexOf(' charset="gb') !== -1 ||
                body.indexOf('=\'text/html; charset=gb') !== -1) {
              body = iconv.decode(originBody, 'gbk')
              gbFlag = true
            }
            handleRespond({req, res, body, gbFlag})
          } else { // non-gzip and non-text body
            let fwdStr = req.headers['X-Forwarded-For'] || req.headers['x-forwarded-for']
            let contentType = proxyRes.headers['content-type']
            let contentLen = proxyRes.headers['content-length']
            res.end(body)
          }
        })
        const setCookieHeaders = proxyRes.headers['set-cookie'] || []
        let datestr = ''
        let datestrOriginHost = ''
        if (setCookieHeaders.length > 0) {
            let curDate = new Date()
            let date = new Date(curDate.getTime() + 7200 * 1000) // 2 hours later
            datestr = date.toUTCString()
            date = new Date(curDate.getTime() + 600 * 1000) // 10 mins later
            datestrOriginHost = date.toUTCString()
        }
        const modifiedSetCookieHeaders = setCookieHeaders
          .map(str => new cookiejar.Cookie(str))
          .map(cookie => {
          if (cookie.path && cookie.path[0] === '/') {
            cookie.domain = `${serverName}`
            cookie.expiration_date = datestr
            cookie.path = `/${httpType}/${host}${cookie.path}`
          }
          cookie.secure = false
          return cookie
          })
          .map(cookie => cookie.toString())
        let cookie_originalHost= new cookiejar.Cookie()
        cookie_originalHost.name = 'ORIGINALHOST'
        cookie_originalHost.value = `${httpType}/${host}`
        cookie_originalHost.domain = `${serverName}`
        cookie_originalHost.expiration_date = datestrOriginHost
        cookie_originalHost.path = `/`
        cookie_originalHost.secure = false
        modifiedSetCookieHeaders.push(cookie_originalHost.toString())
        proxyRes.headers['set-cookie'] =  modifiedSetCookieHeaders
        Object.keys(proxyRes.headers).forEach(function (key) {
          if (key === 'content-security-policy' || key === 'x-frame-options' || (key === 'content-length' && contentTypeIsText(proxyRes.headers) === true)) {
            return
          }
          try {
            if (key === 'content-encoding' && contentTypeIsText(proxyRes.headers) === true) {
                res.setHeader(key, 'gzip') // for text response, we need to set it gzip encoding cuz we will do gzip on it
            } else {
                res.setHeader(key, proxyRes.headers[key])
            }
          } catch(e) {
              //logger.error(`error:${e}`)
              return
          }
        });
        res.statusCode = proxyRes.statusCode

        locationMod302({res, serverName, httpprefix, host, httpType})
        if (res.statusCode === 404) {
            try {
                if (res.headers && res.headers['content-length']) {
                    delete res.headers['content-length'] //remove content-length field
                }
                redirect2HomePage({res, httpprefix, serverName,})
            } catch(e) {
                //logger.error(`error: ${e}`)
            }
            return
        }
      },
      onProxyReq: (proxyReq, req, res) => {
        let myRe = new RegExp(`/http[s]?/${serverName}[0-9:]*?`, 'g') // match group
        req.url = req.url.replace(myRe, '')
        if (req.url.length === 0) {
            req.url = '/'
        }

        let fwdStr = req.headers['X-Forwarded-For'] || req.headers['x-forwarded-for']

        let { host, httpType } = getHostFromReq({req, serverName})
        if (host.indexOf(serverName) !== -1 || host == '' || host.indexOf('.') === -1 || (fwdStr && fwdStr.split(',').length > 3)) { // too many forwardings
            res.status(404).send("{}")
            return
        }
        req.headers['host'] = host
        req.headers['referer'] = host
        if ('origin' in req.headers) { req.headers['origin'] = host }
        let newpath = req.url.replace(`/${httpType}/${host}`, '') || '/'
        var parsed = parse(newpath)
        const parsedQuery = queryString.parse(parsed.query)
        parsed.set('query', queryString.stringify(parsedQuery))
        proxyReq.path = proxyReq.url = parsed
        Object.keys(req.headers).forEach(function (key) {
          // remove nginx/cloudflare/pornhub related headers
          if ((host.indexOf('twitter.com') === -1 && key.indexOf('x-') === 0) ||
              key.indexOf('sec-fetch') === 0 ||
              key.indexOf('only-if-cached') === 0 ||
              key.indexOf('cf-') === 0) {
              proxyReq.removeHeader(key)
              if (key === 'sec-fetch-mode') {
                  proxyReq.setHeader('sec-fetch-mode', 'cors')
              }
              return
          }
          proxyReq.setHeader(key, req.headers[key])
        })
        proxyReq.setHeader('Accept-Encoding', 'gzip')
        proxyReq.setHeader('referer', host)
        if(host === '' || !host) {
            redirect2HomePage({res, httpprefix, serverName,})
            res.end()
        }

      },
    })
    return p
}

module.exports = Proxy;