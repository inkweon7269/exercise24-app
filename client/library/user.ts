import axios from "axios";
import baseUrl from './base.json'

const env: string = process.env.NODE_ENV || 'development'

export const postLogin = (data) => {
    return axios({
        method: 'post',
        url: '/account/login',
        baseURL: baseUrl[env].baseUrl,
        headers: {
            'Content-Type': 'application/json'
        },
        data: data
    })
}