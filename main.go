package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	jwtware "github.com/gofiber/jwt/v2"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

var db *sqlx.DB

const jwtSecret = "mrbaxthazz"

func main() {
	var err error
	db, err = sqlx.Open("mysql", "root:Basbm031197#@tcp(localhost:3306)/banking")
	if err != nil {
		panic(err)
	}
	app := fiber.New()
	app.Use("/hello", jwtware.New(jwtware.Config{
		SigningMethod: "HS256",
		SigningKey:    []byte(jwtSecret),
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			return fiber.ErrUnauthorized
		},
	}))
	app.Post("/signup", Signup)
	app.Post("/login", Login)
	app.Get("/hello", Hello)

	app.Listen(":8000")

}
func Signup(c *fiber.Ctx) error {
	request := SignupRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}

	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity

	}
	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	query := "insert user (username,password) value (?,?)"
	result, err := db.Exec(query, request.Username, string(password))
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	user := User{
		Id:       int(id),
		Username: request.Username,
		Password: request.Password,
	}

	return c.JSON(user)
}

func Login(c *fiber.Ctx) error {
	request := LoginRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}
	user := User{}
	query := "SELECT id,username,password FROM user WHERE username=?"
	err = db.Get(&user, query, request.Username)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}

	//Compare
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}

	cliams := jwt.StandardClaims{
		Issuer:    strconv.Itoa(user.Id),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}

	//gen JWT
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)
	token, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{
		"token": token,
	})
}

func Hello(c *fiber.Ctx) error {
	return c.SendString("Hello World")
}

type User struct {
	Id       int    `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Fiber() {
	app := fiber.New(fiber.Config{
		Prefork: true,
	})

	//Middleware
	app.Use("/hello", func(c *fiber.Ctx) error {
		c.Locals("name", "bas")
		fmt.Println("Before")
		err := c.Next()
		fmt.Println("after")
		return err
	})

	//RequestId
	app.Use(requestid.New())

	//Cors
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "*",
		AllowHeaders: "*",
	}))

	//Logger
	app.Use(logger.New(logger.Config{
		TimeZone: "Asia/Bangkok",
	}))

	//GET
	app.Get("/hello", func(c *fiber.Ctx) error {
		name := c.Locals("name")
		return c.SendString(fmt.Sprintf("GET Hello wolrd %v", name))
	})

	//POST
	app.Post("/hello", func(c *fiber.Ctx) error {
		return c.SendString("POST Hello wolrd")
	})

	//Parameters Optional
	app.Get("/hello/:name/:surname", func(c *fiber.Ctx) error {
		name := c.Params("name")
		surname := c.Params("surname")

		return c.SendString("Name is :" + name + "  surname :" + surname)
	})

	//ParameterInts
	app.Get("/hello/:id", func(c *fiber.Ctx) error {
		id, err := c.ParamsInt("id")
		if err != nil {
			return fiber.ErrBadRequest
		}

		return c.SendString(fmt.Sprintf("ID = %V", id))
	})

	//Query
	app.Get("/query", func(c *fiber.Ctx) error {
		name := c.Query("name")
		return c.SendString("Name is :" + name)
	})

	//Query2
	app.Get("/query2", func(c *fiber.Ctx) error {
		person := Person{}
		c.QueryParser(&person)
		return c.JSON(person)
	})

	//Wild Card
	app.Get("/wildcard/*", func(c *fiber.Ctx) error {
		wildCard := c.Params("*")
		return c.SendString(wildCard)
	})

	//Static file
	app.Static("/", "./wwwroot", fiber.Static{
		Index:         "index.html",
		CacheDuration: time.Second * 10,
	})

	//New Error
	app.Get("/error", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusNotFound, "content not found")
	})

	//Group
	v1 := app.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("Version", "v1")
		return c.Next()
	})
	v1.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello v1")
	})

	v2 := app.Group("/v2", func(c *fiber.Ctx) error {
		c.Set("Version", "v2")
		return c.Next()
	})
	v2.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello v2")
	})

	//Mount
	userApp := fiber.New()
	userApp.Get("/login", func(c *fiber.Ctx) error {
		return c.SendString("Login")
	})
	app.Mount("/user", userApp)

	//Server
	app.Server().MaxConnsPerIP = 1
	app.Get("/server", func(c *fiber.Ctx) error {
		time.Sleep(time.Second * 30)
		return c.SendString("Server")
	})

	//Get ENV
	app.Get("/env", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"BaseUrl":     c.BaseURL(),
			"Hostname":    c.Hostname(),
			"Ip":          c.IP(),
			"Ips":         c.IPs(),
			"OriginalUrl": c.OriginalURL(),
			"Path":        c.Path(),
			"Protocol":    c.Protocol(),
			"Subdomains":  c.Subdomains(),
		})
	})

	app.Post("/body", func(c *fiber.Ctx) error {
		fmt.Println(string(c.Body()))

		person := Person{}
		err := c.BodyParser(&person)
		if err != nil {
			return err
		}
		fiber.NewError(fiber.StatusUnprocessableEntity)
		fmt.Println(person)
		return nil
	})

	app.Post("/body2", func(c *fiber.Ctx) error {
		fmt.Println(string(c.Body()))

		data := map[string]string{}
		err := c.BodyParser(&data)
		if err != nil {
			return err
		}
		fmt.Println(data)
		return nil
	})

	app.Listen(":8000")
}

type Person struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}
