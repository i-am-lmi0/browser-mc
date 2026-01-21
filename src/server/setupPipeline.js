const config = require('../config');
const getSessionId = require('../util/getSessionId');

module.exports = function setupPipeline(proxyServer, sessionStore) {
    proxyServer.addToOnRequestPipeline((req, res, _serverInfo, isRoute) => {
        if (isRoute) return;

        if (config.restrictSessionToIP) {
            const sessionId = getSessionId(req.url);
            const session = sessionId && sessionStore.get(sessionId);
            if (session && session.data.restrictIP && session.data.restrictIP !== config.getIP(req)) {
                res.writeHead(403);
                res.end('Sessions must come from the same IP');
                return true;
            }
        }

        for (const eachHeader of config.stripClientHeaders) {
            delete req.headers[eachHeader];
        }
    });

    proxyServer.addToOnResponsePipeline((req, res, _serverInfo, isRoute, ctx) => {
        if (isRoute) return;

        const headers = ctx.responseHeaders;
        if (!headers) return;

        delete headers['x-frame-options'];
        delete headers['content-security-policy'];
        delete headers['content-security-policy-report-only'];
        delete headers['frame-ancestors'];
    });

    Object.assign(proxyServer.rewriteServerHeaders, config.rewriteServerHeaders);
};
