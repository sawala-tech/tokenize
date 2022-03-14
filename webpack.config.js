const path = require("path")

module.exports = {
  mode: "production",
  entry: {
    main: "./src/index.ts",
  },
  output: {
    path: path.resolve(__dirname, "./dist"),
    filename: "index.js",
    clean: true,
  },
  resolve: {
    extensions: [".ts", ".js"],
  },
  module: {
    rules: [
      {
        test: /\.ts?$/,
        loader: "ts-loader",
      },
    ],
  },
}
