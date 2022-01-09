import * as yup from "yup";

/*
    firstName: yup.string().required('firstName 필수 항목입니다.'),
    email: yup.string().email('유효한 이메일 주소가 아닙니다.').required('email 필수 항목입니다.'),
    password: yup.string().required('password 필수 항목입니다.'),
    gender: yup.string().required('gender 필수 항목입니다.'),
    alarm: yup.string().required('alarm 필수 항목입니다.'),
    option: yup.string().required('option 필수 항목입니다.'),
 */

export const joinSchema = yup.object().shape({
    email: yup.string().email('유효한 이메일 주소가 아닙니다.').required('email 필수 항목입니다.'),
    password: yup.string().required('password 필수 항목입니다.'),
    passwordConfirm: yup.string().oneOf([yup.ref('password'), null], '비밀번호가 일치하지 않습니다.').required('password 필수 항목입니다.'),
});

export const loginSchema = yup.object().shape({
    email: yup.string().email('유효한 이메일 주소가 아닙니다.').required('email 필수 항목입니다.'),
    password: yup.string().required('password 필수 항목입니다.'),
});