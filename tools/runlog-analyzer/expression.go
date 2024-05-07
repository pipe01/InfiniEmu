package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

type ExpressionError error

func ParseRegister(str string) (RunlogRegister, error) {
	if len(str) < 2 {
		return 0, fmt.Errorf("invalid register: %s", str)
	}

	str = strings.ToLower(str)

	if str[0] == 'r' {
		n, err := strconv.Atoi(str[1:])
		if err != nil {
			return 0, fmt.Errorf("invalid register number: %s", str)
		}

		if n < 0 || n > int(RUNLOG_REG_PC) {
			return 0, fmt.Errorf("register number out of range: %d", n)
		}

		return RunlogRegister(n) + RUNLOG_REG_R0, nil
	}

	switch str {
	case "sp":
		return RUNLOG_REG_SP, nil
	case "lr":
		return RUNLOG_REG_LR, nil
	case "pc":
		return RUNLOG_REG_PC, nil
	}

	return 0, fmt.Errorf("invalid register: %s", str)
}

type exprContext struct {
	frames Frames
}

func ExecuteExpression(str string, frames Frames) (ret uint32, err error) {
	var expr ast.Expr

	expr, err = parser.ParseExpr(str)
	if err != nil {
		return 0, err
	}

	ctx := exprContext{frames: frames}

	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(ExpressionError); ok {
				err = e
			} else {
				panic(r)
			}
		}
	}()

	return visitExpression(&ctx, expr), nil
}

func visitExpression(ctx *exprContext, expr ast.Expr) uint32 {
	switch expr := expr.(type) {
	case *ast.ParenExpr:
		return visitExpression(ctx, expr.X)

	case *ast.BasicLit:
		switch expr.Kind {
		case token.INT:
			value, err := strconv.ParseUint(expr.Value, 0, 32)
			if err != nil {
				panic(ExpressionError(fmt.Errorf("invalid number: %v", err)))
			}

			return uint32(value)

		default:
			panic(ExpressionError(fmt.Errorf("unsupported literal type: %v", expr.Kind.String())))
		}

	case *ast.Ident:
		reg, err := ParseRegister(expr.Name)
		if err != nil {
			panic(ExpressionError(fmt.Errorf("invalid register: %v", err)))
		}

		return ctx.frames.Last().Registers[reg]

	case *ast.BinaryExpr:
		left := visitExpression(ctx, expr.X)
		right := visitExpression(ctx, expr.Y)

		switch expr.Op {
		case token.ADD:
			return left + right
		case token.SUB:
			return left - right
		case token.MUL:
			return left * right
		case token.QUO:
			return left / right
		case token.REM:
			return left % right
		case token.AND:
			return left & right
		case token.OR:
			return left | right
		case token.XOR:
			return left ^ right
		case token.AND_NOT:
			return left &^ right
		case token.SHL:
			return left << right
		case token.SHR:
			return left >> right

		default:
			panic(ExpressionError(fmt.Errorf("unsupported binary operator: %s", expr.Op.String())))
		}

	case *ast.UnaryExpr:
		value := visitExpression(ctx, expr.X)

		switch expr.Op {
		case token.SUB:
			return ^value + 1
		}

	case *ast.StarExpr:
		addr := visitExpression(ctx, expr.X)

		value, err := ctx.frames.ReadMemoryAt(addr)
		if err != nil {
			panic(ExpressionError(err))
		}

		return value
	}

	panic(ExpressionError(fmt.Errorf("unsupported expression type: %T", expr)))
}
