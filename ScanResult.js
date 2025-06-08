const { Sequelize, DataTypes } = require("sequelize");
const sequelize = require("../database");

const ScanResult = sequelize.define("ScanResult", {
  id: { type: DataTypes.UUID, defaultValue: Sequelize.UUIDV4, primaryKey: true },
  target: { type: DataTypes.STRING, allowNull: false },
  timestamp: { type: DataTypes.DATE, defaultValue: Sequelize.NOW },
  vulnerabilities: { type: DataTypes.JSON }, // Store scan details
});

module.exports = ScanResult;
