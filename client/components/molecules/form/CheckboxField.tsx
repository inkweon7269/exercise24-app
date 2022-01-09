import React, {FC} from 'react';
import StyledCheckbox, {IPropsCheckbox} from "../../atoms/form/StyledCheckbox";
import {Control, Controller} from "react-hook-form";
import StyledLabel from "../../atoms/form/StyledLabel";
import StyledError from "../../atoms/form/StyledError";

interface IProps extends IPropsCheckbox {
    control: Control;
    label?: string;
    name: string;
    errorMessage?: string;
}

const CheckboxField: FC<IProps> = ({
                                       control,
                                       label,
                                       name,
                                       options,
                                       text,
                                       errorMessage,
                                   }) => {
    return (
        <Controller
            control={control}
            name={name}
            render={({field}) => (
                <StyledLabel label={label}>
                    <StyledCheckbox
                        field={field}
                        text={text}
                        options={options}
                    />
                    <StyledError message={errorMessage}/>
                </StyledLabel>
            )}
        />
    );
};

export default CheckboxField;