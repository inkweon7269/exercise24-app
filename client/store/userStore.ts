import { observable } from "mobx";
import {postLogin} from "../library/user";

const login = async (data: any, callback: any) => {
    try {
        const res = await postLogin(data);
        if (res.status === 200 || res.status === 201) {
            user.token = res.data.token;
            localStorage.setItem('token', res.data.token);

            callback(true, null, '로그인에 성공했습니다.');
        }
    } catch (e) {
        if (e instanceof Error) {
            callback(false, null, e.message);
        }
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