const express = require('express')
const path = require('path')
const fs = require('fs')
//const logger = require('./src/logger')
const Proxy = require('./src/Proxy')

var app = express()
var { blockedSites, urlModify, httpprefix, serverName, locationReplaceMap302, regReplaceMap, siteSpecificReplace, pathReplace } = require('./src/config')

let proxy = Proxy({ blockedSites, urlModify, httpprefix, serverName, locationReplaceMap302, regReplaceMap, siteSpecificReplace, pathReplace})

app.use((req, res, next) => {
    let timestr = new Date().toISOString()
    let myRe = new RegExp(`/http[s]?/${serverName}[0-9:]*?`, 'g') // match group
    req.url = req.url.replace(myRe, '')
    if (req.url.length === 0) {
        req.url = '/'
    }

    //logger.info(`req.url:${req.url}`)
    const dirPath = path.join(__dirname, req.url)
    let fwdStr = req.headers['x-forwarded-for']
    if (fwdStr && fwdStr.split(',').length > 3) { // too many forwardings
        return res.status(404).send('{"error": "too many redirects"}')
    }
    if (req.url === '/' || req.url === '/index.html') {
        res.sendFile(path.join(__dirname, './views/index.html'))
        return
    } else if (req.url === '/style.css') {
        res.sendFile(path.join(__dirname, './views/style.css'))
        return
    } else if (req.url === '/favicon.png') {
        res.sendFile(path.join(__dirname, './views/favicon.png'))
        return
    } else
    if (fs.existsSync(dirPath) && !fs.lstatSync(dirPath).isDirectory()) {
        res.sendFile(dirPath)
        return
    }
    next()
})
app.use(proxy)

let listenport = process.env.PORT || 8888
app.listen(listenport)

console.log(`listening on port: ${listenport}`)
