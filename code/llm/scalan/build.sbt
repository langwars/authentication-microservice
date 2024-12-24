scalaVersion := "2.13.12"
enablePlugins(ScalaNativePlugin)

name := "auth-service"
organization := "com.benchmark"
version := "1.0"

nativeMode := "release-fast"
nativeLinkStubs := true

libraryDependencies ++= Seq(
  "com.lihaoyi" %%% "upickle" % "3.1.3"
)
