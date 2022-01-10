import { observable } from "mobx";
import {postLogin} from "../library/user";

const login = async (data, callback) => {
    try {
        const res = await postLogin(data);
        if (res.status === 200 || res.status === 201) {
            user.token = res.data.token;
            localStorage.setItem('token', res.data.token);

            callback(true, null, '로그인에 성공했습니다.');
        }
    } catch (error) {
        callback(false, null, error.response.data.message);
    }
}

const logOut = async () => {
    localStorage.clear();
    window.location.href = '/';
}

const user = observable({
    token: typeof window == 'object' ? localStorage.getItem('token') ? localStorage.getItem('token') : null : null,
    login,
    logOut,
})

export default user;