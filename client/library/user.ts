import axios from "axios";
import baseUrl from './base.json'

const env: string = process.env.NODE_ENV || 'development'

export const postLogin = (data: any) => {
    return axios({
        method: 'post',
        url: '/account/login',
        baseURL: 'http://localhost:8000',
        headers: {
            'Content-Type': 'application/json'
        },
        data: data
    })
}