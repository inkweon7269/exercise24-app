import React, {FC} from 'react';
import {Checkbox as AntCheckbox} from "antd";
import styled from "styled-components";

export interface IPropsCheckbox {
    field?: any;
    options?: { value: string; label: string }[];
    text?: any;
}

const StyledCheckbox: FC<IPropsCheckbox> = (
    {
        field,
        options,
        text,
    }
) => {
    return (
        <>
            {
                text && (
                    <_StyledCheckbox
                        {...field}
                        onChange={(e) => field.onChange(e.target.checked)}
                        checked={field.value}
                    >
                        {text}
                    </_StyledCheckbox>
                )
            }
            {
                !text && (
                    <_StyledCheckboxGroup
                        {...field}
                        options={options}
                        onChange={(e) => {
                            field.onChange(e);
                        }}
                    />
                )
            }
        </>
    );
};

export default StyledCheckbox;

const _StyledCheckbox = styled(AntCheckbox)`

`;

const _StyledCheckboxGroup = styled(AntCheckbox.Group)`

`;