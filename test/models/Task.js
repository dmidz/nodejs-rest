module.exports = function( sequelize, DataTypes ){
	
	const models = sequelize.models;
	
	return sequelize.define( 'Task', {
		id: { type: DataTypes.INTEGER, primaryKey: true, unique: true, autoIncrement: true },
		title: { type: DataTypes.STRING, allowNull: false/*, defaultValue : 'New Task'*/ },
		content: { type: DataTypes.TEXT, allowNull: true }
	}, {
		underscored: true, freezeTableName: true,
		scopes: {
			collection: function(){//__ returns only root tasks ( with no parent )
				return {
					where: { parent: null },
					attributes: ['id', 'title', 'created_at']
				}
			},
			single: function(){//__ include subtasks as 'children'
				return {
					attributes: ['id', 'title', 'parent', 'content'],
					include: [
						{ model: models.Task.scope( 'task_children' ), as: 'children' }
					]
				}
			},
			user_tasks: function(){//__ include subtasks as 'children'
				return {
					attributes: ['id', 'title', 'parent'],
					include: [
						{ model: models.Task.scope( 'task_children' ), as: 'children' }
					]
				}
			},
			task_children: {
				attributes: ['id', 'user_id']
			}
		}
	} );
};



