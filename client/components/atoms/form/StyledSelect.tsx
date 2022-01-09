import React, {FC} from 'react';
import {Select} from "antd";
import styled from "styled-components";

const AntSelect = Select;

export interface IPropsSelect {
    field?: any;
    options: { value: string; label: string; disabled?: boolean }[];
    placeholder?: string;
    showSearch?: boolean;
    disabled?: boolean;
    width?: string;
    display?: string;
}

const StyledSelect: FC<IPropsSelect> = (
    {
        field,
        options,
        placeholder,
        showSearch,
        disabled,
        width,
        display
    }
) => {
    return (
        <>
            {
                showSearch && (
                    <_StyleSelect
                        {...field}
                        showSearch
                        optionFilterProp="children"
                        filterOption={(input, option) =>
                            option.children.toLowerCase().indexOf(input.toLowerCase()) >= 0
                        }
                        placeholder={placeholder}
                        disabled={disabled}
                        width={width}
                        display={display}
                        onChange={(e) => {
                            field.onChange(e);
                        }}
                    >
                        {options.map((item, key) => (
                            <Select.Option key={key} value={item.value} disabled={item.disabled}>
                                {item.label}
                            </Select.Option>
                        ))}
                    </_StyleSelect>
                )
            }
            {
                !showSearch && (
                    <_StyleSelect
                        {...field}
                        placeholder={placeholder}
                        disabled={disabled}
                        width={width}
                        display={display}
                        onChange={(e) => {
                            field.onChange(e);
                        }}
                    >
                        {options.map((item, key) => (
                            <Select.Option key={key} value={item.value} disabled={item.disabled}>
                                {item.label}
                            </Select.Option>
                        ))}
                    </_StyleSelect>
                )
            }
        </>
    );
};

export default StyledSelect;

const _StyleSelect = styled(AntSelect)`
`;