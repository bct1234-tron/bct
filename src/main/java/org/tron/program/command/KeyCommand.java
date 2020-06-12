package org.tron.program.command;

import java.lang.annotation.*;

/**
 * 命令
 *
 * @Autor Tricky
 * @Date 2020-05-20 09:59:33
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface KeyCommand {
	/**
	 * 命令名称
	 *
	 * @return
	 */
	String value();

	/**
	 * 命令描述
	 *
	 * @return
	 */
	String desc() default "";
}