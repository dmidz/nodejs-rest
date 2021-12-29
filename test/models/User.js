module.exports = function( sequelize, DataTypes ){
	
	const bcrypt = require( 'bcrypt' );
	const models = sequelize.models;
	const salt = bcrypt.genSaltSync( 8 );
	
	return sequelize.define( 'User', {
		id: { type: DataTypes.INTEGER, primaryKey: true, unique: true, autoIncrement: true },
		login: { type: DataTypes.STRING, allowNull: false/*, unique: true*/ },
		disabled: { type: DataTypes.INTEGER, allowNull: true },
		confirmed: { type: DataTypes.INTEGER, allowNull: true },
		password: {
			type: DataTypes.STRING, allowNull: false,
			set( value ){
				this.setDataValue( 'password', bcrypt.hashSync( value, salt ) );
			}
		},
		roles: { type: DataTypes.STRING, allowNull: true },
		scope: {
			type: DataTypes.VIRTUAL,//__ usefull for hapi auth access scope system
			get(){
				return this.getDataValue( 'roles' );
			}
		}
	}, {
		underscored: true,
		freezeTableName: true,// Model tableName will be the same as the model name
		indexes: [
			{ unique: true, fields: ['login'] }
		],
		scopes: {
			collection: {
				//__ TODO : remove login && password & check if auth OK
				attributes: ['id', 'roles']
			},
			single(){
				return {
					//__ TODO : remove login && password & check if auth OK
					attributes: ['id', 'roles'],
					include: [{
						model: models.Task.scope( { method: ['user_tasks'] } ),
						as: 'tasks'
					}]
				};
			}
		}
	} );
};



