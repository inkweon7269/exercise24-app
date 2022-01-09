import React, {FC} from 'react';
import StyledSelect, {IPropsSelect} from "../../atoms/form/StyledSelect";
import {Control, Controller} from "react-hook-form";
import StyledLabel from "../../atoms/form/StyledLabel";
import StyledError from "../../atoms/form/StyledError";

interface IProps extends IPropsSelect {
    control: Control;
    label?: string;
    name: string;
    errorMessage?: string;
}

const SelectField: FC<IProps> = (
    {
        control,
        label,
        name,
        placeholder,
        options,
        errorMessage,
        showSearch
    }
) => {
    return (
        <Controller
            control={control}
            name={name}
            render={({field}) => (
                <StyledLabel label={label}>
                    <StyledSelect
                        field={field}
                        options={options}
                        placeholder={placeholder}
                        showSearch={showSearch}
                    />
                    <StyledError message={errorMessage}/>
                </StyledLabel>
            )}
        />
    );
};

export default SelectField;