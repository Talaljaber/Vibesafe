import chalk from "chalk";
import figlet from "figlet";
import boxen from "boxen";
import { PRODUCT_TAGLINE } from "@vibeguard/shared";

export function printBanner() {
  const logoText = figlet.textSync("VIBEGUARD", {
    font: "Standard",
    horizontalLayout: "full",
  });

  const banner = boxen(chalk.bold.magentaBright(logoText), {
    padding: 1,
    margin: { top: 1, bottom: 1 },
    borderStyle: "round",
    borderColor: "magenta",
    textAlignment: "center",
  });

  console.log(banner);
  console.log(chalk.gray(`  ${PRODUCT_TAGLINE}\n`));
}
