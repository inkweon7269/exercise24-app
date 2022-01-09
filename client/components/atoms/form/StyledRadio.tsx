import React, {FC} from 'react';
import {Radio} from "antd";
import styled from "styled-components";

const AntRadio = Radio.Group;

export interface IPropsRadio {
    field?: any;
    options: { value: string; label: string }[];
    onChange?: (value: any) => void;
}

const StyledRadio: FC<IPropsRadio> = (
    {
        field,
        options,
        onChange
    }
) => {
    return (
        <_StyledRadio
            {...field}
            options={options}
            onChange={(e) => {
                if (onChange) {
                    onChange(e.target.value);
                }
                field.onChange(e);
            }}
        />
    );
};

export default StyledRadio;

const _StyledRadio = styled(AntRadio)`

`;