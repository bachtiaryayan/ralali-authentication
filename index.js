/*
 * author : ralali dev team
 *
 * */
'use strict'

const jwt = require('jwt-simple')
const moment = require('moment')
const key = process.env.TOKEN_SECRET + 'xxxxxxxxxxxxxxxx'
const encryptor = require('simple-encryptor')({
    key,
    hmac: false
});
/**
 * Module exports.
 * @public
 */

module.exports = {
    version: '1.0.1',

    /**
     * Service fot method POST.
     *
     * @param  {String} url
     * @param  {Json} data
     * @return {Object} Callback status 'statusCode' and body 'response'
     */
    ensureAuthenticated: (req, res, next) => {
        if (!req.headers.authorization) {
            return res.status(401).send({
                authorized: false,
                message: 'Full Authentication is Required to Access This Resource'
            });
        }
        let authData = req.headers.authorization.split(' ')
        let token = authData[1];
        if (authData[0] !== process.env.TOKEN_TYPE) {
            return res.status(401).send({
                authorized: false,
                message: 'Invalid Token Type'
            });
        }
        let payload = null;
        try {
            payload = jwt.decode(token, process.env.TOKEN_SECRET);
        }
        catch (err) {
            return res.status(401).send({
                authorized: false,
                message: 'Invalid Token'
            });
        }

        if (payload.exp <= moment().unix()) {
            return res.status(401).send({
                authorized: false,
                message: 'Token Has Expired'
            });
        }
        req.user = payload.sub;
    },

    getTimeJWT: (toket) => {
        let payload = null;
        try {
            payload = jwt.decode(toket, process.env.TOKEN_SECRET);
        }
        catch (err) {
            return res.status(401).send({
                authorized: false,
                message: 'Invalid Token'
            });
        }
        return payload.iat
    },

    createJWT: (id) => {
        const payload = {
            sub: id,
            iat: moment().unix(),
            exp: moment().add(process.env.TOKEN_EXPIRED_TIME, process.env.TOKEN_EXPIRED_UNIT).unix()
        }

        return jwt.encode(payload, process.env.TOKEN_SECRET)
    },

    createAuth: (id) => {
        let data = {
            id: id,
            iat: moment().unix(),
            exp: moment().add(process.env.TOKEN_EXPIRED_TIME, process.env.TOKEN_EXPIRED_UNIT).unix()
        }
        return encryptor.encrypt(data);
    },

    decodeAuth: (req, res, next) => {
        if (!req.headers.authorization) {
            res.status(401).send({
                authorized: false,
                message: 'Full Authentication is Required to Access This Resource'
            });
        }
        let authData = req.headers.authorization.split(' ')
        let token = authData[1];
        if (authData[0] !== process.env.TOKEN_TYPE) {
            res.status(401).send({
                authorized: false,
                message: 'Invalid Token Type'
            });
        }

        let payload = encryptor.decrypt(token)
        if (!payload) {
            res.status(401).send({
                authorized: false,
                message: 'Invalid Token'
            })
        }


        if (payload.exp <= moment().unix()) {
            res.status(401).send({
                authorized: false,
                message: 'Token Has Expired'
            })
        }
        req.user = payload.id
    }
}