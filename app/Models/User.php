<?php

namespace App\Models;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Spatie\Activitylog\Traits\LogsActivity;
use App\Traits\UuidsTrait;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable, SoftDeletes, LogsActivity, UuidsTrait;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'username', 'email', 'password', 'firstname', 'lastname'
    ];

    /**
     * Rule for validation
     * unique validation set on last string
     */
    protected $rules = [
        'username' => 'bail|required|max:190|unique:users,username',
        'email' => 'bail|required|max:190|email|unique:users,email',
        'password' => 'bail|required|max:32|confirmed|min:3',
        'firstname' => 'bail|required|max:190',
        'lastname' => 'max:190',
        'roles' => 'bail|required|array',
        'roles.*' => 'exists:roles,id',
        'avatar' => [
            'nullable',
            'regex:/data:image\/([a-zA-Z]*);base64,([^\"]*)/'
        ],
    ];

    protected static $logFillable = true;
    public $incrementing = false;


    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token', 'pivot'
    ];

    /**
     * The new atribute
     * @var array
     */
    protected $appends = ['fullname'];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }

    public function roles()
    {
        return $this->belongsToMany('App\Models\Role');
    }

    /**
    * @param string|array $roles
    */
    public function authorizeRoles($roles)
    {
        if (is_array($roles)) {
            return $this->hasAnyRole($roles) ||
                abort(401, 'This action is unauthorized. Only ' . implode(',', $roles) . ' can access this action.');
        }

        return $this->hasRole($roles) ||
            abort(401, 'This action is unauthorized. Only ' . $roles . ' can access this action.');

    }

    /**
    * Check multiple roles
    * @param array $roles
    */
    public function hasAnyRole($roles)
    {
        return null !== $this->roles()->whereIn('name', $roles)->first();
    }

    /**
    * Check one role
    * @param string $role
    */
    public function hasRole($role)
    {
        return null !== $this->roles()->where('name', $role)->first();
    }

    /**
    * get fullname
    * @return string
    */
    public function getFullnameAttribute() : string
    {
        return ucwords($this->attributes['firstname'] . ' ' . $this->attributes['lastname']);
    }

    /**
     * Get the administrator flag for the user.
     *
     */
    public function getAvatarAttribute()
    {
        $imageUrl = url('/').'/api/user/' . $this->attributes['id'] . '/avatar/';

        if (!$this->attributes['avatar'])
            $avatar = null;
        else
            $avatar = [
                'original_image' => $imageUrl . 'original@' . $this->attributes['avatar'],
                'thumbnail' => $imageUrl . 'thumbnail@' . $this->attributes['avatar'],
                'filename' => $this->attributes['avatar']
            ];

        return $avatar;
    }
    
    /**
     * Set custom loging description
     */
    public function getDescriptionForEvent(string $eventName)
    {
        return "This user has been {$eventName}";
    }

    /**
     * getter rules
     * 
     * @return Array
     */
    public function getRules()
    {
        return $this->rules;
    }
}
